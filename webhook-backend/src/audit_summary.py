import os
import psycopg2


DB_HOST = os.getenv("DB_HOST", "postgres.db.svc.cluster.local")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "webhook_audit")
DB_USER = os.getenv("DB_USER", "webhook_user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "webhook_pass")


def get_audit_summary():
    """
    Returns aggregated admission audit statistics.
    """

    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            connect_timeout=2
        )

        cur = conn.cursor()

        # =====================================================
        # TOTAL REQUESTS
        # =====================================================
        cur.execute(
            "SELECT COUNT(*) FROM admission_audit_logs"
        )
        total_requests = cur.fetchone()[0]

        # =====================================================
        # ALLOWED REQUESTS
        # =====================================================
        cur.execute(
            """
            SELECT COUNT(*)
            FROM admission_audit_logs
            WHERE decision LIKE 'allow%'
            """
        )
        allowed_requests = cur.fetchone()[0]

        # =====================================================
        # DENIED REQUESTS
        # =====================================================
        cur.execute(
            """
            SELECT COUNT(*)
            FROM admission_audit_logs
            WHERE decision = 'deny'
            """
        )
        denied_requests = cur.fetchone()[0]

        # =====================================================
        # MOST DENIED POLICY
        # =====================================================
        cur.execute(
            """
            SELECT policy, COUNT(*) as count
            FROM admission_audit_logs
            WHERE decision = 'deny'
            GROUP BY policy
            ORDER BY count DESC
            LIMIT 1
            """
        )

        policy_row = cur.fetchone()

        most_denied_policy = {
            "policy": policy_row[0],
            "count": policy_row[1]
        } if policy_row else None

        # =====================================================
        # MOST PROBLEMATIC NAMESPACE
        # =====================================================
        cur.execute(
            """
            SELECT namespace, COUNT(*) as count
            FROM admission_audit_logs
            WHERE decision = 'deny'
            GROUP BY namespace
            ORDER BY count DESC
            LIMIT 1
            """
        )

        namespace_row = cur.fetchone()

        most_problematic_namespace = {
            "namespace": namespace_row[0],
            "count": namespace_row[1]
        } if namespace_row else None

        cur.close()
        conn.close()

        return {
            "total_requests": total_requests,
            "allowed_requests": allowed_requests,
            "denied_requests": denied_requests,
            "most_denied_policy": most_denied_policy,
            "most_problematic_namespace": most_problematic_namespace
        }

    except Exception as e:
        return {
            "error": str(e)
        }

def get_dashboard_stats():
    """
    Returns exact stats structure expected by the UI Dashboard, directly from DB.
    """
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            connect_timeout=2
        )
        cur = conn.cursor()

        stats = {
            "total": 0,
            "success": 0,
            "security": { "total": 0, "breakdown": {} },
            "storage": { "total": 0, "breakdown": {} },
            "resource": { "total": 0, "breakdown": {} }
        }

        # Toplam ve Başarılı İstekler
        cur.execute("SELECT decision, COUNT(*) FROM admission_audit_logs GROUP BY decision")
        rows = cur.fetchall()
        for row in rows:
            decision = row[0]
            count = row[1]
            stats["total"] += count
            if decision.startswith("allow"):
                stats["success"] += count

        # Reddedilen İsteklerin Kırılımı
        cur.execute("SELECT policy, reason, COUNT(*) FROM admission_audit_logs WHERE decision = 'deny' GROUP BY policy, reason")
        deny_rows = cur.fetchall()
        for row in deny_rows:
            policy = row[0]
            reason = row[1]
            count = row[2]

            category = "security"
            if policy == "resources":
                category = "resource"
            elif policy == "storage":
                category = "storage"
            elif policy == "security":
                category = "security"
            else:
                r_low = reason.lower()
                if "resource" in r_low or "cpu" in r_low or "memory" in r_low:
                    category = "resource"
                elif "volume" in r_low or "storage" in r_low or "hostpath" in r_low:
                    category = "storage"

            if len(reason) > 55:
                reason = reason[:55] + "..."

            stats[category]["total"] += count
            stats[category]["breakdown"][reason] = count

        cur.close()
        conn.close()

        return stats

    except Exception as e:
        return {
            "error": str(e)
        }
        
def check_database_health():
    """
    Checks PostgreSQL connection status.
    """

    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            connect_timeout=2
        )

        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()

        cur.close()
        conn.close()

        return {
            "status": "healthy",
            "database": "connected"
        }

    except Exception as e:
        return {
            "status": "unhealthy",
            "database": "unreachable",
            "error": str(e)
        }
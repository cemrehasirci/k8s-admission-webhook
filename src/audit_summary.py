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
import os
import psycopg2
from datetime import datetime


DB_HOST = os.getenv("DB_HOST", "postgres.db.svc.cluster.local")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "webhook_audit")
DB_USER = os.getenv("DB_USER", "webhook_user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "webhook_pass")


def save_audit_log(namespace, pod_name, image, decision, policy, reason, environment):
    """
    Admission kararlarını PostgreSQL'e kaydeder.
    DB hatası olursa webhook karar mekanizmasını bozmaz.
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

        insert_query = """
        INSERT INTO admission_audit_logs
        (namespace, pod_name, image, decision, policy, reason, environment, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
        """

        cur.execute(
            insert_query,
            (
                namespace,
                pod_name,
                image,
                decision,
                policy,
                reason,
                environment,
                datetime.utcnow()
            )
        )

        conn.commit()
        cur.close()
        conn.close()

        print(
            f"[AUDIT] Saved admission decision to PostgreSQL | "
            f"namespace={namespace} pod={pod_name} decision={decision} policy={policy}"
        )

    except Exception as e:
        print(f"[AUDIT_ERROR] PostgreSQL audit log could not be saved: {e}")
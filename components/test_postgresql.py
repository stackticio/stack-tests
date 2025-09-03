# test_postgresql.py - Production version based on actual ENV variables

import os
from typing import List, Dict
import subprocess

def run_command(command: str, env: Dict = None, timeout: int = 10) -> Dict:
    """Helper to run a shell command and capture stdout/stderr/exit code"""
    try:
        completed = subprocess.run(
            command,
            shell=True,
            env=env or os.environ.copy(),
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "exit_code": completed.returncode,
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip()
        }
    except subprocess.TimeoutExpired:
        return {"exit_code": 124, "stdout": "", "stderr": "Timeout"}
    
def test_postgresql_connectivity() -> List[Dict]:
    """Test PostgreSQL server connectivity"""
    host = os.getenv("POSTGRESQL_POSTGRESQL_HOST") or os.getenv("POSTGRES_HOST")
    port = os.getenv("POSTGRESQL_POSTGRESQL_PORT") or os.getenv("POSTGRES_PORT", "5432")
    admin_password = os.getenv("POSTGRESQL_POSTGRESQL_ADMIN_PASSWORD", "")

    conn_str = f"postgresql://postgres:{admin_password}@{host}:{port}/postgres"
    result = run_command(f'psql "{conn_str}" -c "SELECT version();"')

    status = True if result["exit_code"] == 0 and "PostgreSQL" in result["stdout"] else False
    severity = "CRITICAL" if not status else "INFO"

    return [{"name": "postgresql_connectivity", 
            "status": status, 
            "output": result.get('stdout', ''),
            "severity": severity}]


def test_postgresql_list_databases() -> List[Dict]:
    """List all databases"""
    host = os.getenv("POSTGRESQL_POSTGRESQL_HOST") or os.getenv("POSTGRES_HOST")
    port = os.getenv("POSTGRESQL_POSTGRESQL_PORT") or os.getenv("POSTGRES_PORT", "5432")
    admin_password = os.getenv("POSTGRESQL_POSTGRESQL_ADMIN_PASSWORD", "")

    conn_str = f"postgresql://postgres:{admin_password}@{host}:{port}/postgres"
    sql = "SELECT datname, pg_size_pretty(pg_database_size(datname)) as size FROM pg_database WHERE datname NOT IN ('template0', 'template1') ORDER BY pg_database_size(datname) DESC;"
    result = run_command(f'psql "{conn_str}" -c "{sql}"')

    status = True if result["exit_code"] == 0 and "datname" in result["stdout"] else False
    severity = "CRITICAL" if not status else "INFO"

    return [{"name": "postgresql_list_databases", 
            "status": status, 
            "output": result.get('stdout', ''),
            "severity": severity}]


def _get_databases() -> List[Dict]:
    """Parse POSTGRES_DATABASES environment variable"""
    databases = []
    databases_env = os.getenv("POSTGRES_DATABASES", "")
    for db_config in databases_env.split(";"):
        if not db_config.strip():
            continue
        parts = db_config.strip().split(":")
        if len(parts) >= 4:
            databases.append({
                "name": parts[0],
                "user": parts[1],
                "password": parts[2],
                "database": parts[3]
            })
    return databases

def test_db() -> List[Dict]:
    databases = _get_databases()
    results = []

    for db_info in databases:
        results.append(postgresql_db_connectivity(db_info))
        results.append(postgresql_db_write(db_info))
        results.append(postgresql_db_tables(db_info))
    
    return results
        

def postgresql_db_connectivity(db_info: Dict) -> Dict:
    """Test connectivity to a specific database"""
    host = os.getenv("POSTGRESQL_POSTGRESQL_HOST") or os.getenv("POSTGRES_HOST")
    port = os.getenv("POSTGRESQL_POSTGRESQL_PORT") or os.getenv("POSTGRES_PORT", "5432")

    conn_str = f'postgresql://{db_info["user"]}:{db_info["password"]}@{host}:{port}/{db_info["database"]}'
    result = run_command(f'psql "{conn_str}" -c "SELECT current_database(), current_user, version();"')

    status = True if result["exit_code"] == 0 else False
    severity = "CRITICAL" if not status else "INFO"

    return {"name": f'postgresql_{db_info["name"]}_connectivity', 
            "status": status, 
            "output": result.get('stdout', ''),
            "severity": severity}


def postgresql_db_write(db_info: Dict) -> Dict:
    """Test write permissions in a database"""
    host = os.getenv("POSTGRESQL_POSTGRESQL_HOST") or os.getenv("POSTGRES_HOST")
    port = os.getenv("POSTGRESQL_POSTGRESQL_PORT") or os.getenv("POSTGRES_PORT", "5432")

    conn_str = f'postgresql://{db_info["user"]}:{db_info["password"]}@{host}:{port}/{db_info["database"]}'
    sql = '''
    CREATE TEMP TABLE stack_agent_test (
        id SERIAL PRIMARY KEY,
        test_value TEXT,
        created_at TIMESTAMP DEFAULT NOW()
    );
    INSERT INTO stack_agent_test (test_value) VALUES ('test1'), ('test2');
    SELECT COUNT(*) as records FROM stack_agent_test;
    DROP TABLE stack_agent_test;
    '''
    result = run_command(f'psql "{conn_str}" -c "{sql}"')

    status = True if result["exit_code"] == 0 else False
    severity = "CRITICAL" if not status else "INFO"

    return {"name": f'postgresql_{db_info["name"]}_write', 
            "status": status, 
            "output": result.get('stdout', ''),
            "severity": severity}


def postgresql_db_tables(db_info: Dict) -> Dict:
    """List tables in a database"""
    host = os.getenv("POSTGRESQL_POSTGRESQL_HOST") or os.getenv("POSTGRES_HOST")
    port = os.getenv("POSTGRESQL_POSTGRESQL_PORT") or os.getenv("POSTGRES_PORT", "5432")

    conn_str = f'postgresql://{db_info["user"]}:{db_info["password"]}@{host}:{port}/{db_info["database"]}'
    sql = '''
    SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
    FROM pg_tables WHERE schemaname = 'public'
    ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
    LIMIT 20;
    '''
    result = run_command(f'psql "{conn_str}" -c "{sql}"')

    status = True if result["exit_code"] == 0 else False
    severity = "CRITICAL" if not status else "INFO"

    return {"name": f'postgresql_{db_info["name"]}_tables', 
            "status": status, 
            "output": result.get('stdout', ''),
            "severity": severity}


def test_postgresql_connections() -> List[Dict]:
    """Check active connections"""
    host = os.getenv("POSTGRESQL_POSTGRESQL_HOST") or os.getenv("POSTGRES_HOST")
    port = os.getenv("POSTGRESQL_POSTGRESQL_PORT") or os.getenv("POSTGRES_PORT", "5432")
    admin_password = os.getenv("POSTGRESQL_POSTGRESQL_ADMIN_PASSWORD", "")

    conn_str = f"postgresql://postgres:{admin_password}@{host}:{port}/postgres"
    sql = "SELECT datname, usename, application_name, client_addr, state, COUNT(*) as count FROM pg_stat_activity WHERE datname IS NOT NULL GROUP BY datname, usename, application_name, client_addr, state ORDER BY count DESC;"
    result = run_command(f'psql "{conn_str}" -c "{sql}"')

    status = True if result["exit_code"] == 0 else False
    severity = "CRITICAL" if not status else "INFO"

    return [{"name": "postgresql_connections", 
            "status": status, 
            "output": result.get('stdout', ''),
            "severity": severity}]


def test_postgresql_long_queries() -> List[Dict]:
    """Check active connections"""
    host = os.getenv("POSTGRESQL_POSTGRESQL_HOST") or os.getenv("POSTGRES_HOST")
    port = os.getenv("POSTGRESQL_POSTGRESQL_PORT") or os.getenv("POSTGRES_PORT", "5432")
    admin_password = os.getenv("POSTGRESQL_POSTGRESQL_ADMIN_PASSWORD", "")

    conn_str = f"postgresql://postgres:{admin_password}@{host}:{port}/postgres"
    sql = '''
    SELECT pid, age(clock_timestamp(), query_start) as duration, usename, datname, state, LEFT(query, 100) as query_preview
    FROM pg_stat_activity
    WHERE query != '<IDLE>'
      AND query NOT ILIKE '%pg_stat_activity%'
      AND age(clock_timestamp(), query_start) > interval '1 minute'
    ORDER BY query_start
    LIMIT 10;
    '''
    result = run_command(f'psql "{conn_str}" -c "{sql}"')

    status = True if result["exit_code"] == 0 else False
    severity = "CRITICAL" if not status else "INFO"

    return [{"name": "postgresql_long_queries", 
            "status": status, 
            "output": result.get('stdout', ''),
            "severity": severity}]


def test_postgresql_replication() -> List[Dict]:
    """Check replication status"""
    host = os.getenv("POSTGRESQL_POSTGRESQL_HOST") or os.getenv("POSTGRES_HOST")
    port = os.getenv("POSTGRESQL_POSTGRESQL_PORT") or os.getenv("POSTGRES_PORT", "5432")
    admin_password = os.getenv("POSTGRESQL_POSTGRESQL_ADMIN_PASSWORD", "")

    conn_str = f"postgresql://postgres:{admin_password}@{host}:{port}/postgres"
    sql = '''
    SELECT client_addr, state, sync_state,
           pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn)) as lag
    FROM pg_stat_replication;
    '''
    result = run_command(f'psql "{conn_str}" -c "{sql}"')

    status = True if result["exit_code"] == 0 else False
    severity = "CRITICAL" if not status else "INFO"

    return [{"name": "postgresql_replication", 
            "status": status, 
            "output": result.get('stdout', ''),
            "severity": severity}]


def test_postgresql_statistics() -> List[Dict]:
    """Get database statistics"""
    host = os.getenv("POSTGRESQL_POSTGRESQL_HOST") or os.getenv("POSTGRES_HOST")
    port = os.getenv("POSTGRESQL_POSTGRESQL_PORT") or os.getenv("POSTGRES_PORT", "5432")
    admin_password = os.getenv("POSTGRESQL_POSTGRESQL_ADMIN_PASSWORD", "")

    conn_str = f"postgresql://postgres:{admin_password}@{host}:{port}/postgres"
    sql = '''
    SELECT datname, numbackends as connections, xact_commit as commits, xact_rollback as rollbacks,
           blks_read as disk_reads, blks_hit as cache_hits,
           ROUND(100.0 * blks_hit / NULLIF(blks_hit + blks_read, 0), 2) as cache_hit_ratio
    FROM pg_stat_database
    WHERE datname NOT IN ('template0', 'template1', 'postgres')
    ORDER BY numbackends DESC;
    '''
    result = run_command(f'psql "{conn_str}" -c "{sql}"')

    status = True if result["exit_code"] == 0 else False
    severity = "CRITICAL" if not status else "INFO"

    return [{"name": "postgresql_statistics", 
            "status": status, 
            "output": result.get('stdout', ''),
            "severity": severity}]



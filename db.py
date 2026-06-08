"""sub2report 自有 Postgres：连接池 + 建表 + 种子 + 文件迁移 + 数据访问。

所有页面凭证(sites)、告警配置(settings.alerts)、RBAC、审计、时序采样都存这里。
密码哈希在 auth.py（init 时延迟导入，避免循环引用）。
"""
import json
import os
from datetime import datetime, timedelta, timezone

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

DATABASE_URL = os.getenv("S2R_DATABASE_URL", "postgresql://s2r:s2r@sub2report-db:5432/sub2report")
SITES_FILE = os.getenv("SITES_FILE", "/data/sites.json")
ALERTS_FILE = os.getenv("ALERTS_FILE", "/data/alerts.json")

_pool: AsyncConnectionPool | None = None

# 页面/权限/菜单种子（每个功能一个权限码 + 菜单项）
MENUS_SEED = [
    # code, title, path, group, sort
    ("page.usagerealtime", "实时用量查询", "/usagerealtime", "报表", 10),
    ("page.financemodel", "财务收益模型", "/financemodel", "报表", 20),
    ("page.opsdingdongding", "聚合运维监控", "/opsdingdongding", "报表", 30),
    ("page.usagecnusersearch", "CN用量/充值查询", "/usagecnusersearch", "报表", 40),
    ("page.stationkpi", "跨站每日KPI", "/stationkpi", "报表", 50),
    ("page.accounthealth", "上游账号健康", "/accounthealth", "报表", 60),
    ("page.proxyhealth", "代理IP监测(bar6)", "/proxyhealth", "报表", 65),
    ("page.usereconomy", "用户经济看板", "/usereconomy", "报表", 70),
    ("page.revenuereport", "充值/收入报表", "/revenuereport", "报表", 80),
    ("page.modelprofit", "模型利润分解", "/modelprofit", "报表", 90),
    ("page.alertpush", "推送告警(钉钉)", "/alertpush", "报表", 100),
    ("page.settingsites", "站点配置", "/settingsites", "管理", 200),
    ("admin.users", "人员管理", "/admin/users", "管理", 210),
    ("admin.roles", "角色管理", "/admin/roles", "管理", 220),
    ("admin.menus", "菜单管理", "/admin/menus", "管理", 230),
    ("admin.audit", "审计日志", "/admin/audit", "管理", 240),
]

DEFAULT_ADMIN_EMAIL = "nanxb@qq.com"
DEFAULT_ADMIN_PASSWORD = "Asd123456"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  display_name TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  must_change_pwd BOOLEAN NOT NULL DEFAULT FALSE,
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS roles (
  id SERIAL PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  description TEXT DEFAULT '',
  is_system BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE TABLE IF NOT EXISTS permissions (
  code TEXT PRIMARY KEY,
  name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS role_permissions (
  role_id INT REFERENCES roles(id) ON DELETE CASCADE,
  perm_code TEXT REFERENCES permissions(code) ON DELETE CASCADE,
  PRIMARY KEY (role_id, perm_code)
);
CREATE TABLE IF NOT EXISTS user_roles (
  user_id INT REFERENCES users(id) ON DELETE CASCADE,
  role_id INT REFERENCES roles(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, role_id)
);
CREATE TABLE IF NOT EXISTS menus (
  id SERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  path TEXT NOT NULL,
  perm_code TEXT,
  grp TEXT DEFAULT '',
  sort INT DEFAULT 0,
  enabled BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INT REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  ip TEXT DEFAULT '',
  ua TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_id INT,
  email TEXT DEFAULT '',
  action TEXT NOT NULL,
  target TEXT DEFAULT '',
  detail JSONB,
  ip TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sites (
  id SERIAL PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  base_url TEXT DEFAULT '',
  email TEXT DEFAULT '',
  password TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value JSONB
);
CREATE TABLE IF NOT EXISTS capacity_samples (
  id BIGSERIAL PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  site TEXT NOT NULL,
  platform TEXT DEFAULT '',
  in_use DOUBLE PRECISION,
  capacity DOUBLE PRECISION,
  queue DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_capacity_ts ON capacity_samples(ts);
CREATE TABLE IF NOT EXISTS billing_audit (
  run_date DATE NOT NULL,
  site TEXT NOT NULL,
  leaked_count INT DEFAULT 0,
  leaked_amount DOUBLE PRECISION DEFAULT 0,
  detail JSONB,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (run_date, site)
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts);
"""


def pool() -> AsyncConnectionPool:
    assert _pool is not None, "DB pool not initialized"
    return _pool


async def init_db():
    """打开连接池、建表、种子、文件→PG 迁移。幂等。"""
    global _pool
    _pool = AsyncConnectionPool(DATABASE_URL, min_size=1, max_size=6, open=False, kwargs={"row_factory": dict_row})
    await _pool.open(wait=True, timeout=30)
    async with _pool.connection() as conn:
        await conn.execute(SCHEMA)
        await _seed(conn)
        await _migrate_files(conn)


async def _seed(conn):
    # 权限 + 菜单
    for code, title, path, grp, sort in MENUS_SEED:
        await conn.execute(
            "INSERT INTO permissions(code, name) VALUES(%s,%s) ON CONFLICT (code) DO UPDATE SET name=EXCLUDED.name",
            (code, title),
        )
    # 菜单：按 path 唯一性维护（不存在则插）
    for code, title, path, grp, sort in MENUS_SEED:
        cur = await conn.execute("SELECT id FROM menus WHERE path=%s", (path,))
        if not await cur.fetchone():
            await conn.execute(
                "INSERT INTO menus(title, path, perm_code, grp, sort) VALUES(%s,%s,%s,%s,%s)",
                (title, path, code, grp, sort),
            )
    # admin 角色（系统角色，拥有全部权限）
    cur = await conn.execute("SELECT id FROM roles WHERE name='admin'")
    row = await cur.fetchone()
    if not row:
        cur = await conn.execute(
            "INSERT INTO roles(name, description, is_system) VALUES('admin','超级管理员',TRUE) RETURNING id"
        )
        admin_role_id = (await cur.fetchone())["id"]
    else:
        admin_role_id = row["id"]
    # admin 角色挂全部权限（含未来新增）
    await conn.execute(
        "INSERT INTO role_permissions(role_id, perm_code) SELECT %s, code FROM permissions "
        "ON CONFLICT DO NOTHING", (admin_role_id,),
    )
    # 默认管理员用户（仅当 users 为空时创建）
    cur = await conn.execute("SELECT COUNT(*) AS c FROM users")
    if (await cur.fetchone())["c"] == 0:
        from auth import hash_password  # 延迟导入避免循环
        cur = await conn.execute(
            "INSERT INTO users(email, password_hash, display_name, status) VALUES(%s,%s,%s,'active') RETURNING id",
            (DEFAULT_ADMIN_EMAIL, hash_password(DEFAULT_ADMIN_PASSWORD), "管理员"),
        )
        uid = (await cur.fetchone())["id"]
        await conn.execute("INSERT INTO user_roles(user_id, role_id) VALUES(%s,%s)", (uid, admin_role_id))


async def _migrate_files(conn):
    # sites.json → sites 表（仅当表空）
    cur = await conn.execute("SELECT COUNT(*) AS c FROM sites")
    if (await cur.fetchone())["c"] == 0 and os.path.exists(SITES_FILE):
        try:
            data = json.load(open(SITES_FILE, encoding="utf-8"))
        except (ValueError, OSError):
            data = []
        for s in data if isinstance(data, list) else []:
            if not isinstance(s, dict):
                continue
            name = str(s.get("name", "")).strip()
            if not name:
                continue
            await conn.execute(
                "INSERT INTO sites(name, base_url, email, password) VALUES(%s,%s,%s,%s) "
                "ON CONFLICT (name) DO NOTHING",
                (name, str(s.get("base_url", "")).strip().rstrip("/"), str(s.get("email", "")).strip(), str(s.get("password", ""))),
            )
    # alerts.json → settings['alerts']（仅当不存在）
    cur = await conn.execute("SELECT 1 FROM settings WHERE key='alerts'")
    if not await cur.fetchone() and os.path.exists(ALERTS_FILE):
        try:
            data = json.load(open(ALERTS_FILE, encoding="utf-8"))
            if isinstance(data, dict):
                await conn.execute("INSERT INTO settings(key, value) VALUES('alerts',%s)", (Jsonb(data),))
        except (ValueError, OSError):
            pass


# ---------------- sites ----------------
async def sites_list() -> list[dict]:
    async with pool().connection() as conn:
        cur = await conn.execute("SELECT name, base_url, email, password FROM sites ORDER BY name")
        return list(await cur.fetchall())


async def site_find(name: str) -> dict | None:
    if not name:
        return None
    async with pool().connection() as conn:
        cur = await conn.execute(
            "SELECT name, base_url, email, password FROM sites WHERE lower(name)=lower(%s)", (name.strip(),)
        )
        return await cur.fetchone()


async def sites_replace(rows: list[dict]):
    """整表覆盖（rows 已合并好密码）。"""
    async with pool().connection() as conn:
        async with conn.transaction():
            await conn.execute("DELETE FROM sites")
            for r in rows:
                await conn.execute(
                    "INSERT INTO sites(name, base_url, email, password) VALUES(%s,%s,%s,%s)",
                    (r["name"], r["base_url"], r["email"], r["password"]),
                )


# ---------------- settings (alerts 等) ----------------
async def settings_get(key: str, default=None):
    async with pool().connection() as conn:
        cur = await conn.execute("SELECT value FROM settings WHERE key=%s", (key,))
        row = await cur.fetchone()
        return row["value"] if row else default


async def settings_set(key: str, value):
    async with pool().connection() as conn:
        await conn.execute(
            "INSERT INTO settings(key, value) VALUES(%s,%s) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
            (key, Jsonb(value)),
        )


# ---------------- audit ----------------
async def audit(action: str, user=None, target="", detail=None, ip=""):
    try:
        async with pool().connection() as conn:
            await conn.execute(
                "INSERT INTO audit_logs(user_id, email, action, target, detail, ip) VALUES(%s,%s,%s,%s,%s,%s)",
                ((user or {}).get("id"), (user or {}).get("email", ""), action, target,
                 Jsonb(detail) if detail is not None else None, ip),
            )
    except Exception:
        pass


async def audit_list(limit=200):
    async with pool().connection() as conn:
        cur = await conn.execute("SELECT * FROM audit_logs ORDER BY ts DESC LIMIT %s", (limit,))
        return list(await cur.fetchall())


# ---------------- users / roles / permissions / menus ----------------
async def user_by_email(email: str) -> dict | None:
    async with pool().connection() as conn:
        cur = await conn.execute("SELECT * FROM users WHERE lower(email)=lower(%s)", (email.strip(),))
        return await cur.fetchone()


async def user_by_id(uid: int) -> dict | None:
    async with pool().connection() as conn:
        cur = await conn.execute("SELECT * FROM users WHERE id=%s", (uid,))
        return await cur.fetchone()


async def user_perms(uid: int) -> set[str]:
    async with pool().connection() as conn:
        cur = await conn.execute(
            "SELECT DISTINCT rp.perm_code FROM user_roles ur "
            "JOIN role_permissions rp ON rp.role_id=ur.role_id WHERE ur.user_id=%s", (uid,)
        )
        return {r["perm_code"] for r in await cur.fetchall()}


async def user_role_ids(uid: int) -> list[int]:
    async with pool().connection() as conn:
        cur = await conn.execute("SELECT role_id FROM user_roles WHERE user_id=%s", (uid,))
        return [r["role_id"] for r in await cur.fetchall()]


async def users_list() -> list[dict]:
    async with pool().connection() as conn:
        cur = await conn.execute(
            "SELECT u.id,u.email,u.display_name,u.status,u.last_login_at,u.created_at, "
            "COALESCE(array_agg(r.name) FILTER (WHERE r.name IS NOT NULL),'{}') AS roles "
            "FROM users u LEFT JOIN user_roles ur ON ur.user_id=u.id "
            "LEFT JOIN roles r ON r.id=ur.role_id GROUP BY u.id ORDER BY u.id"
        )
        return list(await cur.fetchall())


async def user_create(email, password_hash, display_name, role_ids):
    async with pool().connection() as conn:
        async with conn.transaction():
            cur = await conn.execute(
                "INSERT INTO users(email,password_hash,display_name) VALUES(%s,%s,%s) RETURNING id",
                (email, password_hash, display_name),
            )
            uid = (await cur.fetchone())["id"]
            for rid in role_ids:
                await conn.execute("INSERT INTO user_roles(user_id,role_id) VALUES(%s,%s) ON CONFLICT DO NOTHING", (uid, rid))
        return uid


async def user_update(uid, display_name=None, status=None, role_ids=None, password_hash=None):
    async with pool().connection() as conn:
        async with conn.transaction():
            if display_name is not None:
                await conn.execute("UPDATE users SET display_name=%s WHERE id=%s", (display_name, uid))
            if status is not None:
                await conn.execute("UPDATE users SET status=%s WHERE id=%s", (status, uid))
            if password_hash is not None:
                await conn.execute("UPDATE users SET password_hash=%s, must_change_pwd=FALSE WHERE id=%s", (password_hash, uid))
            if role_ids is not None:
                await conn.execute("DELETE FROM user_roles WHERE user_id=%s", (uid,))
                for rid in role_ids:
                    await conn.execute("INSERT INTO user_roles(user_id,role_id) VALUES(%s,%s)", (uid, rid))


async def user_delete(uid):
    async with pool().connection() as conn:
        await conn.execute("DELETE FROM users WHERE id=%s", (uid,))


async def set_password(uid, password_hash):
    async with pool().connection() as conn:
        await conn.execute("UPDATE users SET password_hash=%s, must_change_pwd=FALSE WHERE id=%s", (password_hash, uid))


async def touch_login(uid):
    async with pool().connection() as conn:
        await conn.execute("UPDATE users SET last_login_at=now() WHERE id=%s", (uid,))


async def roles_list() -> list[dict]:
    async with pool().connection() as conn:
        cur = await conn.execute(
            "SELECT r.id,r.name,r.description,r.is_system, "
            "COALESCE(array_agg(rp.perm_code) FILTER (WHERE rp.perm_code IS NOT NULL),'{}') AS perms "
            "FROM roles r LEFT JOIN role_permissions rp ON rp.role_id=r.id GROUP BY r.id ORDER BY r.id"
        )
        return list(await cur.fetchall())


async def role_create(name, description, perm_codes):
    async with pool().connection() as conn:
        async with conn.transaction():
            cur = await conn.execute("INSERT INTO roles(name,description) VALUES(%s,%s) RETURNING id", (name, description))
            rid = (await cur.fetchone())["id"]
            for c in perm_codes:
                await conn.execute("INSERT INTO role_permissions(role_id,perm_code) VALUES(%s,%s) ON CONFLICT DO NOTHING", (rid, c))
        return rid


async def role_update(rid, name=None, description=None, perm_codes=None):
    async with pool().connection() as conn:
        async with conn.transaction():
            if name is not None:
                await conn.execute("UPDATE roles SET name=%s WHERE id=%s", (name, rid))
            if description is not None:
                await conn.execute("UPDATE roles SET description=%s WHERE id=%s", (description, rid))
            if perm_codes is not None:
                await conn.execute("DELETE FROM role_permissions WHERE role_id=%s", (rid,))
                for c in perm_codes:
                    await conn.execute("INSERT INTO role_permissions(role_id,perm_code) VALUES(%s,%s)", (rid, c))


async def role_delete(rid):
    async with pool().connection() as conn:
        cur = await conn.execute("SELECT is_system FROM roles WHERE id=%s", (rid,))
        row = await cur.fetchone()
        if row and row["is_system"]:
            raise ValueError("系统角色不可删除")
        await conn.execute("DELETE FROM roles WHERE id=%s", (rid,))


async def permissions_list() -> list[dict]:
    async with pool().connection() as conn:
        cur = await conn.execute("SELECT code, name FROM permissions ORDER BY code")
        return list(await cur.fetchall())


async def menus_list() -> list[dict]:
    async with pool().connection() as conn:
        cur = await conn.execute("SELECT * FROM menus ORDER BY sort, id")
        return list(await cur.fetchall())


async def menu_create(title, path, perm_code, grp, sort):
    async with pool().connection() as conn:
        await conn.execute("INSERT INTO menus(title,path,perm_code,grp,sort) VALUES(%s,%s,%s,%s,%s)", (title, path, perm_code, grp, sort))


async def menu_update(mid, title=None, path=None, perm_code=None, grp=None, sort=None, enabled=None):
    async with pool().connection() as conn:
        fields, vals = [], []
        for k, v in (("title", title), ("path", path), ("perm_code", perm_code), ("grp", grp), ("sort", sort), ("enabled", enabled)):
            if v is not None:
                fields.append(f"{k}=%s")
                vals.append(v)
        if fields:
            vals.append(mid)
            await conn.execute(f"UPDATE menus SET {','.join(fields)} WHERE id=%s", vals)


async def menu_delete(mid):
    async with pool().connection() as conn:
        await conn.execute("DELETE FROM menus WHERE id=%s", (mid,))


# ---------------- sessions ----------------
async def session_create(token, user_id, ip, ua, ttl_days=7):
    exp = datetime.now(timezone.utc) + timedelta(days=ttl_days)
    async with pool().connection() as conn:
        await conn.execute(
            "INSERT INTO sessions(token,user_id,expires_at,ip,ua) VALUES(%s,%s,%s,%s,%s)",
            (token, user_id, exp, ip, ua),
        )


async def session_user(token) -> dict | None:
    if not token:
        return None
    async with pool().connection() as conn:
        cur = await conn.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id "
            "WHERE s.token=%s AND s.expires_at>now() AND u.status='active'", (token,)
        )
        return await cur.fetchone()


async def session_delete(token):
    async with pool().connection() as conn:
        await conn.execute("DELETE FROM sessions WHERE token=%s", (token,))


# ---------------- capacity / billing (后续阶段用) ----------------
async def capacity_insert(site, platform, in_use, capacity, queue):
    async with pool().connection() as conn:
        await conn.execute(
            "INSERT INTO capacity_samples(site,platform,in_use,capacity,queue) VALUES(%s,%s,%s,%s,%s)",
            (site, platform, in_use, capacity, queue),
        )


async def close():
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None

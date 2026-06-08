import asyncio
import base64
import hashlib
import hmac
import json
import os
import threading
import time
import urllib.parse
from datetime import date, datetime, timedelta

import httpx

# sub2api 的 trend 接口返回 'YYYY-MM-DD HH:00'，HH 已经是后端 PG 容器时区下
# 的小时（实测 ue1-api 的 PG 容器 TZ=Asia/Shanghai，直接给出北京小时；同时
# 我们在请求里固定传 timezone=Asia/Shanghai，让 sub2api 按北京时区切日界）。
# 因此这里直接读字符串里的 HH，不做额外时区平移 —— 平移过会把已经是北京时间
# 的桶再加 8 小时，导致整张图错位。
from fastapi import FastAPI, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

import db
import auth

app = FastAPI(title="sub2report", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory="templates")
app.add_middleware(auth.AuthMiddleware)
app.include_router(auth.router)


@app.on_event("startup")
async def _startup_db():
    await db.init_db()


@app.on_event("shutdown")
async def _shutdown_db():
    await db.close()


# ---------------- 站点配置中心（已并入 PG sites 表，对外契约不变） ----------------
async def _load_sites() -> list[dict]:
    return await db.sites_list()


async def _find_site(name: str) -> dict | None:
    return await db.site_find(name)


@app.get("/settingsites")
async def settingsites_page(request: Request):
    return templates.TemplateResponse("settingsites.html", {"request": request})


@app.get("/api/sites")
async def get_sites():
    """列出站点，绝不返回明文密码（只标记是否已设置）。供各页面下拉与配置界面使用。"""
    sites = [
        {
            "name": s["name"],
            "base_url": s["base_url"],
            "email": s["email"],
            "has_password": bool(s["password"]),
        }
        for s in await _load_sites()
    ]
    return {"ok": True, "sites": sites}


@app.post("/api/sites")
async def post_sites(request: Request):
    """保存整份站点列表。密码留空=沿用同名旧站已存密码（密码只进不出）。"""
    try:
        payload = await request.json()
    except Exception:
        return {"ok": False, "error": "请求体必须是 JSON"}
    rows = payload.get("sites") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return {"ok": False, "error": "sites 必须是数组"}

    old_by_name = {s["name"].lower(): s for s in await _load_sites()}
    out: list[dict] = []
    seen: set[str] = set()
    for r in rows:
        if not isinstance(r, dict):
            continue
        name = str(r.get("name", "")).strip()
        if not name:
            return {"ok": False, "error": "存在空的站点名称"}
        key = name.lower()
        if key in seen:
            return {"ok": False, "error": f"站点名称重复: {name}"}
        seen.add(key)
        pwd = str(r.get("password", ""))
        if not pwd:  # 留空 → 沿用旧密码
            old = old_by_name.get(key)
            pwd = old["password"] if old else ""
        out.append({
            "name": name,
            "base_url": str(r.get("base_url", "")).strip().rstrip("/"),
            "email": str(r.get("email", "")).strip(),
            "password": pwd,
        })
    try:
        await db.sites_replace(out)
    except Exception as e:
        return {"ok": False, "error": f"写入失败: {e}"}
    return {"ok": True, "count": len(out)}


@app.post("/api/site-test")
async def post_site_test(request: Request):
    """用某个已配置站点的凭证试登一次，验证可用性。"""
    try:
        payload = await request.json()
    except Exception:
        return {"ok": False, "error": "请求体必须是 JSON"}
    name = str((payload or {}).get("name", "")).strip()
    site = await _find_site(name)
    if not site:
        return {"ok": False, "error": f"未找到站点: {name}"}
    if not site["base_url"] or not site["email"] or not site["password"]:
        return {"ok": False, "error": "站点信息不完整(地址/邮箱/密码)"}
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            await _login(client, site["base_url"], site["email"], site["password"])
        except Exception as e:
            return {"ok": False, "error": str(e)}
    return {"ok": True}

MAX_PARALLEL = 4  # per-request concurrency cap when fanning out per-model trend queries
MODEL_HARD_CAP = 30  # safety net; if a day has more models than this, the tail is dropped
OBS_TTL = 25  # seconds; covers a 30s auto-refresh cycle
CMP_TTL = 30 * 60  # historical day rarely changes
MODELS_TTL = 60  # day-level model list — same day still appends, refresh once a minute


def _yesterday() -> str:
    return (date.today() - timedelta(days=1)).isoformat()


@app.get("/usagerealtime")
async def index(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "today": date.today().isoformat(),
            "yesterday": _yesterday(),
        },
    )


# ---------------- tiny TTL cache (key -> (expires_at, payload)) ----------------
_CACHE: dict[tuple, tuple[float, object]] = {}


def _cache_get(key: tuple):
    item = _CACHE.get(key)
    if not item:
        return None
    exp, val = item
    if exp < time.time():
        _CACHE.pop(key, None)
        return None
    return val


def _cache_set(key: tuple, val, ttl: float):
    _CACHE[key] = (time.time() + ttl, val)


# ---------------- sub2api client helpers ----------------
async def _login(client: httpx.AsyncClient, base_url: str, email: str, password: str) -> str:
    resp = await client.post(
        f"{base_url}/api/v1/auth/login",
        json={"email": email, "password": password},
        timeout=15,
    )
    if resp.status_code != 200:
        detail = ""
        try:
            detail = resp.json().get("message", "")
        except Exception:
            pass
        raise RuntimeError(
            f"Login failed ({resp.status_code}): {detail or 'check email/password'}"
        )
    data = resp.json().get("data", resp.json())
    jwt = data.get("access_token")
    if not jwt:
        raise RuntimeError("Login response missing access_token")
    return jwt


async def _find_user_id(client: httpx.AsyncClient, base_url: str, jwt: str, email: str) -> int | None:
    resp = await client.get(
        f"{base_url}/api/v1/admin/users",
        headers={"Authorization": f"Bearer {jwt}"},
        params={"search": email, "page": 1, "page_size": 20},
        timeout=10,
    )
    if resp.status_code != 200:
        return None
    data = resp.json().get("data", resp.json())
    users = data.get("items", data.get("users", data.get("list", [])))
    if isinstance(users, dict):
        users = users.get("items", users.get("list", []))
    # exact match first
    for u in users:
        if (u.get("email") or "").lower() == email.lower():
            return u.get("id")
    return None


async def _get_models(
    client: httpx.AsyncClient, base_url: str, jwt: str, day: str, user_id: int | None
) -> list[dict]:
    """Returns model stats for the day, sorted by total_tokens desc. Cheap: uses
    dashboard/models which aggregates over usage_logs by day (already indexed by created_at)."""
    params = {"start_date": day, "end_date": day, "timezone": "Asia/Shanghai"}
    if user_id:
        params["user_id"] = user_id
    resp = await client.get(
        f"{base_url}/api/v1/admin/dashboard/models",
        headers={"Authorization": f"Bearer {jwt}"},
        params=params,
        timeout=15,
    )
    if resp.status_code != 200:
        return []
    body = resp.json()
    data = body.get("data", body)
    models = data.get("models", []) or []
    # sort desc by total tokens
    def _tot(m):
        if m.get("total_tokens") is not None:
            return m["total_tokens"]
        return (
            (m.get("input_tokens", 0) or 0)
            + (m.get("output_tokens", 0) or 0)
            + (m.get("cache_creation_tokens", 0) or 0)
            + (m.get("cache_read_tokens", 0) or 0)
        )
    models.sort(key=_tot, reverse=True)
    return models


async def _get_trend(
    client: httpx.AsyncClient,
    base_url: str,
    jwt: str,
    day: str,
    user_id: int | None,
    model: str | None,
) -> list[dict]:
    """Hourly trend for a day, optionally filtered by model. Without model filter
    this hits the pre-aggregated usage_dashboard_hourly table (cheap).
    With model filter it scans usage_logs but the WHERE is (created_at, model)
    over a single day — small range."""
    params: dict = {"start_date": day, "end_date": day, "granularity": "hour", "timezone": "Asia/Shanghai"}
    if user_id:
        params["user_id"] = user_id
    if model:
        params["model"] = model
    resp = await client.get(
        f"{base_url}/api/v1/admin/dashboard/trend",
        headers={"Authorization": f"Bearer {jwt}"},
        params=params,
        timeout=20,
    )
    if resp.status_code != 200:
        return []
    body = resp.json()
    data = body.get("data", body)
    return data.get("trend", []) or []


# ---------------- bucketing ----------------
def _hour_of(date_str: str) -> int | None:
    """Parse sub2api's hour-bucket date string ('YYYY-MM-DD HH:00') and return
    the hour. We don't reinterpret the timezone — the backend has already
    bucketed by its configured TZ (Asia/Shanghai for ue1-api), and we ask for
    timezone=Asia/Shanghai when calling /trend so the day boundaries match."""
    if not date_str:
        return None
    s = date_str.replace("T", " ").strip()
    try:
        return int(s.split(" ")[1][:2])
    except (IndexError, ValueError):
        return None


def _zero_hours() -> list[int]:
    return [0] * 24


def _zero_hours_f() -> list[float]:
    return [0.0] * 24


def _trend_to_hours(trend: list[dict]) -> dict[str, list]:
    """Convert a trend list into per-metric 24-slot arrays."""
    out: dict[str, list] = {
        "total_tokens": _zero_hours(),
        "input_tokens": _zero_hours(),
        "output_tokens": _zero_hours(),
        "cache_creation_tokens": _zero_hours(),
        "cache_read_tokens": _zero_hours(),
        "requests": _zero_hours(),
        "cost": _zero_hours_f(),
        "actual_cost": _zero_hours_f(),
    }
    for p in trend:
        h = _hour_of(p.get("date", ""))
        if h is None or not (0 <= h <= 23):
            continue
        for k in out.keys():
            v = p.get(k, 0) or 0
            out[k][h] = v
    # Ensure total_tokens has a value even if API didn't return it.
    for h in range(24):
        if out["total_tokens"][h] == 0 and (
            out["input_tokens"][h] or out["output_tokens"][h]
            or out["cache_creation_tokens"][h] or out["cache_read_tokens"][h]
        ):
            out["total_tokens"][h] = (
                out["input_tokens"][h]
                + out["output_tokens"][h]
                + out["cache_creation_tokens"][h]
                + out["cache_read_tokens"][h]
            )
    return out


# ---------------- day-level fetch with caching + concurrency cap ----------------
async def _fetch_day_stacked(
    client: httpx.AsyncClient,
    base_url: str,
    jwt: str,
    day: str,
    user_id: int | None,
    sem: asyncio.Semaphore,
    ttl: float,
) -> dict:
    """Fetch a day's per-model hourly breakdown, top-K + 'other'.

    Returns:
        {
          "models": [<modelName1>, ..., "其他"],  # legend order
          "by_model": { modelName: {metric: [24 ints]} },  # includes "其他"
          "total": {metric: [24 ints]},  # unfiltered hourly total for the day
        }

    Caches by (base_url, day, user_id) so a 30s auto-refresh against the
    observation day reuses the result within TTL; the comparison day stays
    cached for 30 min by the caller's larger ttl.
    """
    cache_key = ("stacked", base_url, day, user_id or 0)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    # 1) Pull model list for the day (cheap, daily aggregation, cached separately)
    models_key = ("models", base_url, day, user_id or 0)
    models = _cache_get(models_key)
    if models is None:
        models = await _get_models(client, base_url, jwt, day, user_id)
        _cache_set(models_key, models, MODELS_TTL)

    model_names = [m.get("model") for m in models if m.get("model")][:MODEL_HARD_CAP]

    # 2) Fetch hourly trend for each model in parallel (bounded). Also fetch the
    #    un-filtered hourly total separately because that one hits the
    #    pre-aggregated table (basically free) and is handy for summaries.
    async def _bounded(coro):
        async with sem:
            return await coro

    tasks = [_bounded(_get_trend(client, base_url, jwt, day, user_id, None))]
    for m in model_names:
        tasks.append(_bounded(_get_trend(client, base_url, jwt, day, user_id, m)))
    results = await asyncio.gather(*tasks, return_exceptions=True)

    def _safe(r):
        return r if isinstance(r, list) else []

    total_hours = _trend_to_hours(_safe(results[0]))
    by_model: dict[str, dict] = {}
    for i, m in enumerate(model_names, start=1):
        by_model[m] = _trend_to_hours(_safe(results[i]))

    payload = {"models": model_names, "by_model": by_model, "total": total_hours}
    _cache_set(cache_key, payload, ttl)
    return payload


# ---------------- main endpoint ----------------
@app.post("/api/report")
async def post_report(
    site: str = Form(...),
    target_email: str = Form(""),
    observation_date: str = Form(...),
    comparison_date: str = Form(...),
    refresh_observation_only: str = Form(""),
):
    for d in (observation_date, comparison_date):
        try:
            datetime.strptime(d, "%Y-%m-%d")
        except ValueError:
            return {"error": "Invalid date format, use YYYY-MM-DD"}

    st = await _find_site(site)
    if not st:
        return {"error": f"未找到站点: {site}"}
    base_url = st["base_url"]
    email = st["email"]
    password = st["password"]
    if not base_url or not email or not password:
        return {"error": f"站点「{site}」信息不完整(地址/邮箱/密码)"}
    target_email = target_email.strip()
    only_obs = refresh_observation_only.lower() in ("1", "true", "yes")

    async with httpx.AsyncClient(timeout=20) as client:
        try:
            jwt = await _login(client, base_url, email, password)
        except RuntimeError as e:
            return {"error": str(e)}

        user_id = None
        target_user = {"email": "全部用户"}
        if target_email:
            try:
                uid = await _find_user_id(client, base_url, jwt, target_email)
            except Exception:
                uid = None
            if uid is None:
                return {"error": f"User not found: {target_email}"}
            user_id = uid
            target_user = {"email": target_email, "id": uid}

        sem = asyncio.Semaphore(MAX_PARALLEL)

        try:
            if only_obs:
                obs = await _fetch_day_stacked(
                    client, base_url, jwt, observation_date, user_id, sem, OBS_TTL
                )
                cmp_ = None
            else:
                obs, cmp_ = await asyncio.gather(
                    _fetch_day_stacked(
                        client, base_url, jwt, observation_date, user_id, sem, OBS_TTL
                    ),
                    _fetch_day_stacked(
                        client, base_url, jwt, comparison_date, user_id, sem, CMP_TTL
                    ),
                )
        except Exception as e:
            return {"error": f"Request failed: {str(e)}"}

    payload = {
        "base_url": base_url,
        "observation_date": observation_date,
        "comparison_date": comparison_date,
        "target_user": target_user,
        "observation": obs,
        "server_time": datetime.now().isoformat(timespec="seconds"),
    }
    if cmp_ is not None:
        payload["comparison"] = cmp_
    return payload


# ============================================================================
# 聚合运维监控 (aggregate ops dashboard)
# 输入 N 个站点 (base_url + admin email/password)，并发调用各站
# /api/v1/admin/ops/dashboard/overview，把运维指标汇总成每站一行。
# ============================================================================

OPS_TTL = 25  # 秒；配合前端 30s 自动刷新，避免重复打同一个站
OPS_MAX_PARALLEL = 10  # 同时查询的站点数上限


def _num(v):
    """Return a finite number or None (mirrors the frontend's typeof===number guard)."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        try:
            f = float(v)
        except (TypeError, ValueError):
            return None
        if f != f or f in (float("inf"), float("-inf")):
            return None
        return v
    return None


def _flatten_overview(ov: dict) -> dict:
    """Extract the metrics we render from an OpsDashboardOverview payload.
    Every field is .get()-guarded; missing -> None so the UI shows '-'."""
    sm = ov.get("system_metrics") or {}
    qps = ov.get("qps") or {}
    tps = ov.get("tps") or {}
    ttft = ov.get("ttft") or {}
    duration = ov.get("duration") or {}
    jobs = ov.get("job_heartbeats") or []

    # job 摘要：统计最近一次结果为失败/有 last_error 的任务
    job_total = len(jobs)
    job_failed = 0
    failed_names = []
    for j in jobs:
        res = (j.get("last_result") or "").lower()
        has_err = bool(j.get("last_error"))
        if res in ("error", "failed", "failure") or (has_err and res not in ("success", "ok")):
            job_failed += 1
            if j.get("job_name"):
                failed_names.append(j.get("job_name"))

    sla = _num(ov.get("sla"))
    error_rate = _num(ov.get("error_rate"))
    upstream_error_rate = _num(ov.get("upstream_error_rate"))
    qps_current = _num(qps.get("current"))

    return {
        "health_score": _num(ov.get("health_score")),
        # idle：QPS=0 且 error_rate=0 → 前端原版判定系统空闲（健康分显示灰）
        "idle": (qps_current or 0) == 0 and (error_rate or 0) == 0,
        # system
        "cpu_usage_percent": _num(sm.get("cpu_usage_percent")),
        "memory_usage_percent": _num(sm.get("memory_usage_percent")),
        "memory_used_mb": _num(sm.get("memory_used_mb")),
        "memory_total_mb": _num(sm.get("memory_total_mb")),
        "db_ok": sm.get("db_ok"),
        "redis_ok": sm.get("redis_ok"),
        "db_conn_active": _num(sm.get("db_conn_active")),
        "db_conn_idle": _num(sm.get("db_conn_idle")),
        "db_conn_waiting": _num(sm.get("db_conn_waiting")),
        "db_max_open_conns": _num(sm.get("db_max_open_conns")),
        "redis_conn_total": _num(sm.get("redis_conn_total")),
        "redis_conn_idle": _num(sm.get("redis_conn_idle")),
        "redis_pool_size": _num(sm.get("redis_pool_size")),
        "goroutine_count": _num(sm.get("goroutine_count")),
        "concurrency_queue_depth": _num(sm.get("concurrency_queue_depth")),
        "account_switch_count": _num(sm.get("account_switch_count")),
        # jobs
        "job_total": job_total,
        "job_failed": job_failed,
        "job_failed_names": failed_names[:5],
        # traffic
        "qps_current": qps_current,
        "qps_peak": _num(qps.get("peak")),
        "tps_current": _num(tps.get("current")),
        "tps_peak": _num(tps.get("peak")),
        # counts
        "request_count_total": _num(ov.get("request_count_total")),
        "success_count": _num(ov.get("success_count")),
        "error_count_total": _num(ov.get("error_count_total")),
        "token_consumed": _num(ov.get("token_consumed")),
        # rates (0~1 小数，前端 ×100 成百分比)
        "sla": sla,
        "sla_percent": None if sla is None else sla * 100,
        "error_rate": error_rate,
        "error_rate_percent": None if error_rate is None else error_rate * 100,
        "upstream_error_rate": upstream_error_rate,
        "upstream_error_rate_percent": None if upstream_error_rate is None else upstream_error_rate * 100,
        "upstream_error_count_excl_429_529": _num(ov.get("upstream_error_count_excl_429_529")),
        "upstream_429_count": _num(ov.get("upstream_429_count")),
        "upstream_529_count": _num(ov.get("upstream_529_count")),
        # latency
        "ttft_p99_ms": _num(ttft.get("p99_ms")),
        "ttft_p95_ms": _num(ttft.get("p95_ms")),
        "ttft_p50_ms": _num(ttft.get("p50_ms")),
        "duration_p99_ms": _num(duration.get("p99_ms")),
        "duration_p50_ms": _num(duration.get("p50_ms")),
    }


async def _fetch_station_ops(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    name: str,
    base_url: str,
    email: str,
    password: str,
    time_range: str = "1h",
) -> dict:
    """Login + fetch ops overview for one station. Never raises; failures are
    returned as {ok: False, error: ...} so one bad station can't sink the batch."""
    base_url = (base_url or "").strip().rstrip("/")
    name = (name or "").strip() or base_url
    result = {"name": name, "base_url": base_url, "ok": False}

    if not base_url:
        result["error"] = "缺少站点地址"
        return result

    cache_key = ("ops", base_url, email, time_range)
    cached = _cache_get(cache_key)
    if cached is not None:
        out = dict(cached)
        out["name"] = name  # 名称以本次请求为准
        out["cached"] = True
        return out

    async with sem:
        try:
            jwt = await _login(client, base_url, email, password)
        except RuntimeError as e:
            result["error"] = str(e)
            return result
        except Exception as e:
            result["error"] = f"登录异常: {e}"
            return result

        try:
            resp = await client.get(
                f"{base_url}/api/v1/admin/ops/dashboard/overview",
                headers={"Authorization": f"Bearer {jwt}"},
                params={"time_range": time_range},
                timeout=20,
            )
        except Exception as e:
            result["error"] = f"请求 overview 失败: {e}"
            return result

    if resp.status_code != 200:
        detail = ""
        try:
            detail = resp.json().get("message", "")
        except Exception:
            detail = (resp.text or "")[:200]
        result["error"] = f"overview 返回 {resp.status_code}: {detail or '可能未启用运维监控'}"
        return result

    try:
        body = resp.json()
    except Exception as e:
        result["error"] = f"解析 overview JSON 失败: {e}"
        return result

    ov = body.get("data", body)
    if not isinstance(ov, dict):
        result["error"] = "overview 数据格式异常"
        return result

    result["ok"] = True
    result["metrics"] = _flatten_overview(ov)
    _cache_set(cache_key, result, OPS_TTL)
    return result


@app.get("/opsdingdongding")
async def ops_page(request: Request):
    return templates.TemplateResponse("ops.html", {"request": request})


@app.post("/api/ops-aggregate")
async def post_ops_aggregate(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return {"error": "请求体必须是 JSON"}

    # names 省略或为空 → 查全部已配置站点；否则按名筛选（保持给定顺序）
    names = payload.get("names") if isinstance(payload, dict) else None
    all_sites = await _load_sites()
    if isinstance(names, list) and names:
        wanted = [str(n).strip().lower() for n in names if str(n).strip()]
        by_name = {s["name"].lower(): s for s in all_sites}
        stations = [by_name[n] for n in wanted if n in by_name]
    else:
        stations = all_sites
    if not stations:
        return {"error": "未配置任何站点，请先到「站点配置」添加"}
    stations = stations[:50]  # hard cap

    time_range = str(payload.get("time_range", "1h")).strip() or "1h"
    if time_range not in ("5m", "30m", "1h", "6h", "24h"):
        time_range = "1h"

    sem = asyncio.Semaphore(OPS_MAX_PARALLEL)
    async with httpx.AsyncClient(timeout=25) as client:
        tasks = [
            _fetch_station_ops(
                client,
                sem,
                s["name"],
                s["base_url"],
                s["email"],
                s["password"],
                time_range,
            )
            for s in stations
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    out = []
    for r in results:
        if isinstance(r, dict):
            out.append(r)
        else:
            out.append({"name": "?", "base_url": "", "ok": False, "error": f"内部错误: {r}"})

    return {
        "stations": out,
        "server_time": datetime.now().isoformat(timespec="seconds"),
    }


# ============================================================================
# 单站运维明细 (on-demand drill-down)
# 前端点开某一行才调用，按平台并发/吞吐趋势/时长分布/错误分布/请求错误Top20/
# 上游错误Top20。默认时间窗口 1h。短 TTL 缓存，避免重复点击重复打站。
# ============================================================================

DETAIL_TTL = 60  # 秒；明细面板手动点开，缓存 60s 即可
DETAIL_TOPN = 20  # 错误明细条数


def _unwrap(body):
    """sub2api 统一响应 {code,message,data}，取 data；非包裹结构原样返回。"""
    if isinstance(body, dict) and "data" in body:
        return body.get("data")
    return body


async def _get_json(client, base_url, jwt, path, params=None):
    """GET 一个 admin 接口，返回 (ok, data_or_errmsg)。不抛异常。"""
    try:
        resp = await client.get(
            f"{base_url}{path}",
            headers={"Authorization": f"Bearer {jwt}"},
            params=params or {},
            timeout=20,
        )
    except Exception as e:
        return False, f"{path} 请求异常: {e}"
    if resp.status_code != 200:
        detail = ""
        try:
            detail = resp.json().get("message", "")
        except Exception:
            detail = (resp.text or "")[:120]
        return False, f"{path} 返回 {resp.status_code}: {detail}"
    try:
        return True, _unwrap(resp.json())
    except Exception as e:
        return False, f"{path} JSON 解析失败: {e}"


def _items_of(data):
    """分页响应 data 为 {items,total,...}；取 items 列表。"""
    if isinstance(data, dict):
        items = data.get("items")
        if isinstance(items, list):
            return items
    if isinstance(data, list):
        return data
    return []


async def _fetch_station_detail(
    client: httpx.AsyncClient,
    name: str,
    base_url: str,
    email: str,
    password: str,
    time_range: str,
) -> dict:
    """登录 + 并发拉取一个站的全部明细接口。单接口失败不影响其他接口。"""
    base_url = (base_url or "").strip().rstrip("/")
    name = (name or "").strip() or base_url
    result = {"name": name, "base_url": base_url, "ok": False}
    if not base_url:
        result["error"] = "缺少站点地址"
        return result

    cache_key = ("ops_detail", base_url, email, time_range)
    cached = _cache_get(cache_key)
    if cached is not None:
        out = dict(cached)
        out["name"] = name
        out["cached"] = True
        return out

    try:
        jwt = await _login(client, base_url, email, password)
    except RuntimeError as e:
        result["error"] = str(e)
        return result
    except Exception as e:
        result["error"] = f"登录异常: {e}"
        return result

    tr = {"time_range": time_range}
    paged = {"time_range": time_range, "page": 1, "page_size": DETAIL_TOPN}

    (
        (c_ok, c_data),
        (t_ok, t_data),
        (l_ok, l_data),
        (e_ok, e_data),
        (re_ok, re_data),
        (ue_ok, ue_data),
    ) = await asyncio.gather(
        _get_json(client, base_url, jwt, "/api/v1/admin/ops/concurrency"),
        _get_json(client, base_url, jwt, "/api/v1/admin/ops/dashboard/throughput-trend", tr),
        _get_json(client, base_url, jwt, "/api/v1/admin/ops/dashboard/latency-histogram", tr),
        _get_json(client, base_url, jwt, "/api/v1/admin/ops/dashboard/error-distribution", tr),
        _get_json(client, base_url, jwt, "/api/v1/admin/ops/request-errors", paged),
        _get_json(client, base_url, jwt, "/api/v1/admin/ops/upstream-errors", paged),
    )

    # 按平台并发/排队：data.platform 是 {platform: info} 映射
    concurrency = []
    if c_ok and isinstance(c_data, dict):
        plat = c_data.get("platform") or {}
        if isinstance(plat, dict):
            for p, info in plat.items():
                if isinstance(info, dict):
                    concurrency.append({
                        "platform": info.get("platform") or p,
                        "current_in_use": info.get("current_in_use"),
                        "max_capacity": info.get("max_capacity"),
                        "load_percentage": info.get("load_percentage"),
                        "waiting_in_queue": info.get("waiting_in_queue"),
                    })
        concurrency.sort(key=lambda x: (x.get("waiting_in_queue") or 0, x.get("current_in_use") or 0), reverse=True)

    # 按平台吞吐：data.by_platform
    throughput = []
    if t_ok and isinstance(t_data, dict):
        bp = t_data.get("by_platform") or []
        if isinstance(bp, list):
            for it in bp:
                if isinstance(it, dict):
                    throughput.append({
                        "platform": it.get("platform"),
                        "request_count": it.get("request_count"),
                        "token_consumed": it.get("token_consumed"),
                    })
        throughput.sort(key=lambda x: (x.get("request_count") or 0), reverse=True)

    # 时长分布直方图：data.buckets [{range,count}]
    latency = []
    if l_ok and isinstance(l_data, dict):
        for b in (l_data.get("buckets") or []):
            if isinstance(b, dict):
                latency.append({"range": b.get("range"), "count": b.get("count")})

    # 错误分布：data.items [{status_code,total,sla,business_limited}]
    err_dist = []
    if e_ok and isinstance(e_data, dict):
        for it in (e_data.get("items") or []):
            if isinstance(it, dict):
                err_dist.append({
                    "status_code": it.get("status_code"),
                    "total": it.get("total"),
                    "sla": it.get("sla"),
                    "business_limited": it.get("business_limited"),
                })
        err_dist.sort(key=lambda x: (x.get("total") or 0), reverse=True)

    def _err_rows(ok, data):
        rows = []
        if not ok:
            return rows
        for it in _items_of(data)[:DETAIL_TOPN]:
            if not isinstance(it, dict):
                continue
            rows.append({
                "id": it.get("id"),
                "created_at": it.get("created_at"),
                "status_code": it.get("status_code"),
                "phase": it.get("phase"),
                "type": it.get("type"),
                "error_source": it.get("error_source"),
                "severity": it.get("severity"),
                "platform": it.get("platform"),
                "model": it.get("requested_model") or it.get("model") or it.get("upstream_model"),
                "account_name": it.get("account_name"),
                "user_email": it.get("user_email"),
                "message": it.get("message"),
            })
        return rows

    detail = {
        "time_range": time_range,
        "concurrency": concurrency,
        "throughput": throughput,
        "latency": latency,
        "error_distribution": err_dist,
        "request_errors": _err_rows(re_ok, re_data),
        "upstream_errors": _err_rows(ue_ok, ue_data),
        "errors": {  # 各子接口若失败，把错误文案带回前端提示
            k: v for k, v in {
                "concurrency": None if c_ok else c_data,
                "throughput": None if t_ok else t_data,
                "latency": None if l_ok else l_data,
                "error_distribution": None if e_ok else e_data,
                "request_errors": None if re_ok else re_data,
                "upstream_errors": None if ue_ok else ue_data,
            }.items() if v
        },
    }

    result["ok"] = True
    result["detail"] = detail
    _cache_set(cache_key, result, DETAIL_TTL)
    return result


@app.post("/api/ops-detail")
async def post_ops_detail(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return {"error": "请求体必须是 JSON"}
    if not isinstance(payload, dict):
        return {"error": "请求体格式错误"}

    name = str(payload.get("name", "")).strip()
    st = await _find_site(name)
    if not st:
        return {"error": f"未找到站点: {name}"}
    if not st["base_url"]:
        return {"error": "缺少站点地址"}
    time_range = str(payload.get("time_range", "1h")).strip() or "1h"
    if time_range not in ("1h", "6h", "24h"):
        time_range = "1h"

    async with httpx.AsyncClient(timeout=25) as client:
        res = await _fetch_station_detail(
            client,
            st["name"],
            st["base_url"],
            st["email"],
            st["password"],
            time_range,
        )
    res["server_time"] = datetime.now().isoformat(timespec="seconds")
    return res


# ============================================================================
# 财务收益模型 (/finance)
# 选定时间段 + 站点 + 用户 -> 拉取该用户每天分平台(GPT/Claude/Gemini)的
# actual_cost(实际扣除)。后端只返回原始每日分平台消费额 e，收益换算全在前端
# 做(改百分比参数本地秒算，不重新打 sub2api)。
# ============================================================================

FINANCE_MAX_DAYS = 92  # 时间跨度上限，避免一次并发打太多天给 sub2api 加压
FINANCE_TODAY_TTL = 60  # 当天数据仍在累加，缓存 60s
FINANCE_PAST_TTL = 30 * 60  # 历史日基本不变，缓存 30min


def _classify_platform(model: str) -> str | None:
    """按模型名前缀归类到 gpt/claude/gemini，其余返回 None(忽略)。"""
    m = (model or "").strip().lower()
    if not m:
        return None
    if m.startswith(("gpt", "o1", "o3", "o4", "chatgpt")):
        return "gpt"
    if m.startswith("claude"):
        return "claude"
    if m.startswith("gemini"):
        return "gemini"
    return None


async def _find_user(client: httpx.AsyncClient, base_url: str, jwt: str, ident: str) -> dict | None:
    """按用户名或邮箱精确匹配用户，返回 {id, username, email}。"""
    ident = (ident or "").strip()
    if not ident:
        return None
    ok, data = await _get_json(
        client, base_url, jwt, "/api/v1/admin/users",
        {"search": ident, "page": 1, "page_size": 50},
    )
    if not ok:
        return None
    users = _items_of(data)
    if not users and isinstance(data, dict):
        users = data.get("users", data.get("list", [])) or []
    low = ident.lower()
    for u in users:
        if not isinstance(u, dict):
            continue
        if (u.get("username") or "").lower() == low or (u.get("email") or "").lower() == low:
            return {"id": u.get("id"), "username": u.get("username"), "email": u.get("email")}
    return None


def _date_range(start: str, end: str) -> list[str]:
    s = date.fromisoformat(start)
    e = date.fromisoformat(end)
    if e < s:
        s, e = e, s
    out = []
    d = s
    while d <= e:
        out.append(d.isoformat())
        d += timedelta(days=1)
    return out


FINANCE_MAX_USERS = 50  # 单次结算用户数上限


async def _fetch_user_days(
    client: httpx.AsyncClient,
    base_url: str,
    jwt: str,
    user_id: int,
    days: list[str],
    sem: asyncio.Semaphore,
) -> list[dict]:
    """已解析的用户，按天拉取分平台 actual_cost。共用外部 semaphore 限流。"""
    today_str = date.today().isoformat()

    async def one_day(day: str) -> dict:
        cache_key = ("finance", base_url, user_id, day)
        cached = _cache_get(cache_key)
        if cached is not None:
            return cached
        async with sem:
            models = await _get_models(client, base_url, jwt, day, user_id)
        bucket = {"date": day, "gpt": 0.0, "claude": 0.0, "gemini": 0.0}
        for m in models:
            plat = _classify_platform(m.get("model", ""))
            if plat is None:
                continue
            try:
                bucket[plat] += float(m.get("actual_cost", 0) or 0)
            except (TypeError, ValueError):
                pass
        ttl = FINANCE_TODAY_TTL if day >= today_str else FINANCE_PAST_TTL
        _cache_set(cache_key, bucket, ttl)
        return bucket

    results = await asyncio.gather(*[one_day(d) for d in days])
    results.sort(key=lambda r: r["date"])
    return results


async def _fetch_multi_user_daily_platform_cost(
    client: httpx.AsyncClient,
    users: list[dict],
    start: str,
    end: str,
) -> dict:
    """多站点多用户:每个 user 自带所属站点(base_url/email/password)。
    按 (base_url,email,password) 分组，每个站点只登录一次;再逐用户(各自一行)
    拉取每天分平台 actual_cost。单站登录失败 / 单用户找不到都只影响相关用户。"""
    try:
        days = _date_range(start, end)
    except Exception:
        return {"ok": False, "error": "日期格式错误，应为 YYYY-MM-DD"}
    if not days:
        return {"ok": False, "error": "时间段为空"}
    if len(days) > FINANCE_MAX_DAYS:
        return {"ok": False, "error": f"时间跨度过大({len(days)} 天)，请控制在 {FINANCE_MAX_DAYS} 天内"}

    clean = []
    for i, u in enumerate(users):
        if not isinstance(u, dict):
            continue
        base_url = str(u.get("base_url", "")).strip().rstrip("/")
        username = str(u.get("username", "")).strip()
        if not base_url or not username:
            continue
        clean.append({
            "key": u.get("key", i),
            "station": str(u.get("station_name", "")).strip() or base_url,
            "base_url": base_url,
            "email": str(u.get("email", "")).strip(),
            "password": str(u.get("password", "")),
            "username": username,
        })
    if not clean:
        return {"ok": False, "error": "请至少填写一个「站点 + 用户名」"}
    if len(clean) > FINANCE_MAX_USERS:
        return {"ok": False, "error": f"用户数过多({len(clean)})，请控制在 {FINANCE_MAX_USERS} 个内"}

    # 每个站点(base_url+email+password)只登录一次
    station_jwt: dict[tuple, object] = {}

    async def login_station(key: tuple):
        base_url, email, password = key
        try:
            station_jwt[key] = await _login(client, base_url, email, password)
        except Exception as e:
            station_jwt[key] = RuntimeError(f"登录失败: {e}")

    uniq = {(u["base_url"], u["email"], u["password"]) for u in clean}
    await asyncio.gather(*[login_station(k) for k in uniq])

    sem = asyncio.Semaphore(MAX_PARALLEL)  # 全局共享，跨站点×用户×天限流

    async def one_user(u: dict) -> dict:
        skey = (u["base_url"], u["email"], u["password"])
        jwt = station_jwt.get(skey)
        base = {"key": u["key"], "username": u["username"], "station": u["station"]}
        if isinstance(jwt, Exception) or not jwt:
            return {**base, "ok": False, "error": str(jwt) if jwt else "登录失败"}
        user = await _find_user(client, u["base_url"], jwt, u["username"])
        if not user or not user.get("id"):
            return {**base, "ok": False, "error": f"未找到用户: {u['username']}"}
        rows = await _fetch_user_days(client, u["base_url"], jwt, user["id"], days, sem)
        return {**base, "ok": True, "user": user, "days": rows}

    results = await asyncio.gather(*[one_user(u) for u in clean])
    return {"ok": True, "results": list(results)}


@app.get("/financemodel")
async def finance_page(request: Request):
    return templates.TemplateResponse(
        "finance.html",
        {
            "request": request,
            "today": date.today().isoformat(),
            "week_ago": (date.today() - timedelta(days=6)).isoformat(),
        },
    )


@app.post("/api/finance")
async def post_finance(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return {"ok": False, "error": "请求体必须是 JSON"}
    if not isinstance(payload, dict):
        return {"ok": False, "error": "请求体格式错误"}

    users = payload.get("users")
    if not isinstance(users, list) or not users:
        return {"ok": False, "error": "请至少填写一个「站点 + 用户名」"}
    start = str(payload.get("start", "")).strip()
    end = str(payload.get("end", "")).strip()
    if not start or not end:
        return {"ok": False, "error": "缺少时间段"}

    # 浏览器只传 {station_name, username, key}；在服务端按站点名补齐凭证
    enriched = []
    for u in users:
        if not isinstance(u, dict):
            continue
        station_name = str(u.get("station_name", "")).strip()
        st = await _find_site(station_name)
        enriched.append({
            "key": u.get("key"),
            "station_name": station_name,
            "base_url": st["base_url"] if st else "",
            "email": st["email"] if st else "",
            "password": st["password"] if st else "",
            "username": str(u.get("username", "")).strip(),
        })

    async with httpx.AsyncClient(timeout=25) as client:
        res = await _fetch_multi_user_daily_platform_cost(client, enriched, start, end)
    res["server_time"] = datetime.now().isoformat(timespec="seconds")
    return res


# ---------------- CN 用户用量查询(凭证取自站点配置中名为 "CN" 的站点) ----------------
@app.get("/usagecnusersearch")
async def usage_cn_search_page(request: Request):
    return templates.TemplateResponse("usagecnsearch.html", {"request": request})


async def _cn_site() -> dict | None:
    """取站点配置里名为 'CN' 的站点（usagecnsearch 默认用它）。"""
    return await _find_site("CN")


async def _cn_find_user(client: httpx.AsyncClient, base_url: str, jwt: str, email: str) -> dict | None:
    resp = await client.get(
        f"{base_url}/api/v1/admin/users",
        headers={"Authorization": f"Bearer {jwt}"},
        params={"search": email, "page": 1, "page_size": 20},
        timeout=10,
    )
    if resp.status_code != 200:
        return None
    data = resp.json().get("data", resp.json())
    users = data.get("items", data.get("users", data.get("list", [])))
    if isinstance(users, dict):
        users = users.get("items", users.get("list", []))
    el = email.lower()
    for u in users:
        if isinstance(u, dict) and (u.get("email") or "").lower() == el:
            return u
    return None


@app.post("/api/usage-cn-search")
async def post_usage_cn_search(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return {"ok": False, "error": "请求体必须是 JSON"}
    email = str((payload or {}).get("email", "")).strip()
    if not email:
        return {"ok": False, "error": "请输入用户邮箱"}

    site = await _cn_site()
    if not site or not site["base_url"]:
        return {"ok": False, "error": "未配置名为 CN 的站点，请到「站点配置」添加"}
    cn_base, cn_email, cn_pass = site["base_url"], site["email"], site["password"]

    async with httpx.AsyncClient(timeout=25) as client:
        try:
            jwt = await _login(client, cn_base, cn_email, cn_pass)
        except Exception as e:
            return {"ok": False, "error": f"服务暂时不可用: {e}"}

        user = await _cn_find_user(client, cn_base, jwt, email)
        if not user or not user.get("id"):
            return {"ok": False, "found": False, "error": f"未找到该用户: {email}"}

        uid = user["id"]
        today = date.today()
        days = [(today - timedelta(days=i)).isoformat() for i in range(6, -1, -1)]
        sem = asyncio.Semaphore(MAX_PARALLEL)

        async def one_day(day: str) -> dict:
            async with sem:
                models = await _get_models(client, cn_base, jwt, day, uid)
            cost = 0.0
            tokens = 0
            for m in models:
                try:
                    cost += float(m.get("actual_cost", 0) or 0)
                except (TypeError, ValueError):
                    pass
                try:
                    tokens += int(m.get("total_tokens", 0) or 0)
                except (TypeError, ValueError):
                    pass
            return {"date": day, "cost": round(cost, 6), "tokens": tokens}

        rows = await asyncio.gather(*[one_day(d) for d in days])
        rows = sorted(rows, key=lambda r: r["date"])

    total_cost = round(sum(r["cost"] for r in rows), 6)
    total_tokens = sum(r["tokens"] for r in rows)
    try:
        bal = float(user.get("balance", 0) or 0)
    except (TypeError, ValueError):
        bal = 0.0
    return {
        "ok": True,
        "found": True,
        "email": user.get("email", email),
        "balance": bal,
        "days": rows,
        "total_cost": total_cost,
        "total_tokens": total_tokens,
        "today": today.isoformat(),
        "server_time": datetime.now().isoformat(timespec="seconds"),
    }


# ---------------- CN 用户充值记录查询(redeem-codes used_by 该用户) ----------------
@app.post("/api/usage-cn-recharge")
async def post_usage_cn_recharge(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return {"ok": False, "error": "请求体必须是 JSON"}
    email = str((payload or {}).get("email", "")).strip()
    if not email:
        return {"ok": False, "error": "请输入用户邮箱"}

    site = await _cn_site()
    if not site or not site["base_url"]:
        return {"ok": False, "error": "未配置名为 CN 的站点，请到「站点配置」添加"}
    cn_base, cn_email, cn_pass = site["base_url"], site["email"], site["password"]

    async with httpx.AsyncClient(timeout=25) as client:
        try:
            jwt = await _login(client, cn_base, cn_email, cn_pass)
        except Exception as e:
            return {"ok": False, "error": f"服务暂时不可用: {e}"}

        user = await _cn_find_user(client, cn_base, jwt, email)
        if not user or not user.get("id"):
            return {"ok": False, "found": False, "error": f"未找到该用户: {email}"}

        uid = user["id"]
        headers = {"Authorization": f"Bearer {jwt}"}
        # used_by/user_id 过滤被后端忽略,只能拉全部已使用的兑换码后本地按 used_by 过滤
        matched: list[dict] = []
        page = 1
        page_size = 100
        while page <= 50:
            try:
                resp = await client.get(
                    f"{cn_base}/api/v1/admin/redeem-codes",
                    headers=headers,
                    params={"status": "used", "page": page, "page_size": page_size},
                    timeout=15,
                )
            except Exception:
                break
            if resp.status_code != 200:
                break
            data = resp.json().get("data", {}) or {}
            items = data.get("items", []) or []
            for it in items:
                if it.get("used_by") == uid:
                    matched.append(it)
            pages = data.get("pages") or 1
            if page >= pages or not items:
                break
            page += 1

        def _sort_key(it: dict):
            return str(it.get("used_at") or it.get("created_at") or "")

        matched.sort(key=_sort_key, reverse=True)
        recent = matched[:7]

        records = []
        for it in recent:
            try:
                amount = float(it.get("value", 0) or 0)
            except (TypeError, ValueError):
                amount = 0.0
            records.append({
                "amount": amount,
                "time": it.get("used_at") or it.get("created_at") or "",
                "type": it.get("type") or "",
            })

    try:
        bal = float(user.get("balance", 0) or 0)
    except (TypeError, ValueError):
        bal = 0.0
    return {
        "ok": True,
        "found": True,
        "email": user.get("email", email),
        "balance": bal,
        "records": records,
        "count": len(records),
        "server_time": datetime.now().isoformat(timespec="seconds"),
    }


# ============================================================================
# 新增报表（站点凭证统一取自 sites.json；浏览器不传密码）
#   /stationkpi     跨站每日 KPI 对比     -> /api/station-kpi
#   /accounthealth  上游账号健康看板       -> /api/account-health
#   /usereconomy    用户经济看板          -> /api/user-economy
#   /revenuereport  充值/收入报表         -> /api/revenue
#   /modelprofit    模型利润分解          -> /api/model-profit
#   /alertpush      推送告警(钉钉)        -> /api/alert-config /alert-test /alert-check
# ============================================================================

def _gnum(v):
    """尽量转成数字，失败返回 0。"""
    try:
        if v is None:
            return 0
        return float(v)
    except (TypeError, ValueError):
        return 0


async def _fanout_sites(fn, names=None):
    """对所有(或指定)已配置站点并发执行 fn(client, site)，每站返回一个 dict。
    单站异常不影响整体。"""
    sites = await _load_sites()
    if names:
        wanted = {str(n).strip().lower() for n in names if str(n).strip()}
        sites = [s for s in sites if s["name"].lower() in wanted]
    if not sites:
        return []
    async with httpx.AsyncClient(timeout=30) as client:
        results = await asyncio.gather(
            *[fn(client, s) for s in sites], return_exceptions=True
        )
    out = []
    for s, r in zip(sites, results):
        if isinstance(r, dict):
            out.append(r)
        else:
            out.append({"name": s["name"], "base_url": s["base_url"], "ok": False, "error": f"内部错误: {r}"})
    return out


async def _get_all_pages(client, base_url, jwt, path, params, max_pages=80, page_size=100):
    """翻页拉全量列表（分页响应 {items,total,pages}）。"""
    items = []
    page = 1
    while page <= max_pages:
        ok, data = await _get_json(client, base_url, jwt, path, {**params, "page": page, "page_size": page_size})
        if not ok:
            break
        batch = _items_of(data)
        items.extend(batch)
        pages = data.get("pages") if isinstance(data, dict) else None
        if not batch or (pages and page >= pages):
            break
        page += 1
    return items


# ---------------- 跨站每日 KPI 对比 ----------------
@app.get("/stationkpi")
async def stationkpi_page(request: Request):
    return templates.TemplateResponse("stationkpi.html", {"request": request})


@app.post("/api/station-kpi")
async def post_station_kpi(request: Request):
    async def one(client, s):
        res = {"name": s["name"], "base_url": s["base_url"], "ok": False}
        if not s["base_url"]:
            res["error"] = "缺少站点地址"
            return res
        try:
            jwt = await _login(client, s["base_url"], s["email"], s["password"])
        except Exception as e:
            res["error"] = str(e)
            return res
        ok, data = await _get_json(client, s["base_url"], jwt, "/api/v1/admin/dashboard/stats")
        if not ok or not isinstance(data, dict):
            res["error"] = "获取 stats 失败"
            return res
        g = _gnum
        res.update({
            "ok": True,
            "today_requests": g(data.get("today_requests")),
            "today_tokens": g(data.get("today_tokens")),
            "today_actual_cost": g(data.get("today_actual_cost")),
            "today_cost": g(data.get("today_cost")),
            "today_new_users": g(data.get("today_new_users")),
            "active_users": g(data.get("active_users")),
            "total_users": g(data.get("total_users")),
            "total_accounts": g(data.get("total_accounts")),
            "normal_accounts": g(data.get("normal_accounts")),
            "error_accounts": g(data.get("error_accounts")),
            "overload_accounts": g(data.get("overload_accounts")),
            "ratelimit_accounts": g(data.get("ratelimit_accounts")),
            "rpm": g(data.get("rpm")),
            "tpm": g(data.get("tpm")),
            "avg_duration_ms": g(data.get("average_duration_ms")),
        })
        return res

    stations = await _fanout_sites(one)
    return {"ok": True, "stations": stations, "server_time": datetime.now().isoformat(timespec="seconds")}


# ---------------- 上游账号健康看板 ----------------
@app.get("/accounthealth")
async def accounthealth_page(request: Request):
    return templates.TemplateResponse("accounthealth.html", {"request": request})


def _account_problem(a: dict) -> bool:
    if a.get("schedulable") is False:
        return True
    if a.get("temp_unschedulable_until") or a.get("overload_until") or a.get("rate_limit_reset_at"):
        return True
    st = (a.get("status") or "").lower()
    if st and st not in ("active", "normal", "ok", "enabled", "schedulable"):
        return True
    if a.get("error_message"):
        return True
    return False


@app.post("/api/account-health")
async def post_account_health(request: Request):
    async def one(client, s):
        res = {"name": s["name"], "base_url": s["base_url"], "ok": False}
        if not s["base_url"]:
            res["error"] = "缺少站点地址"
            return res
        try:
            jwt = await _login(client, s["base_url"], s["email"], s["password"])
        except Exception as e:
            res["error"] = str(e)
            return res
        ok, stats = await _get_json(client, s["base_url"], jwt, "/api/v1/admin/dashboard/stats")
        summary = {}
        if ok and isinstance(stats, dict):
            summary = {
                "total": _gnum(stats.get("total_accounts")),
                "normal": _gnum(stats.get("normal_accounts")),
                "error": _gnum(stats.get("error_accounts")),
                "overload": _gnum(stats.get("overload_accounts")),
                "ratelimit": _gnum(stats.get("ratelimit_accounts")),
            }
        accounts = await _get_all_pages(client, s["base_url"], jwt, "/api/v1/admin/accounts", {})
        rows = []
        for a in accounts:
            if not isinstance(a, dict):
                continue
            groups = a.get("account_groups") or []
            gnames = []
            for ag in groups:
                if isinstance(ag, dict) and isinstance(ag.get("group"), dict):
                    n = ag["group"].get("name")
                    if n:
                        gnames.append(n)
            rows.append({
                "id": a.get("id"),
                "name": a.get("name"),
                "platform": a.get("platform"),
                "status": a.get("status"),
                "schedulable": a.get("schedulable"),
                "concurrency": a.get("concurrency"),
                "error_message": a.get("error_message") or "",
                "temp_unschedulable_until": a.get("temp_unschedulable_until"),
                "temp_unschedulable_reason": a.get("temp_unschedulable_reason") or "",
                "rate_limited_at": a.get("rate_limited_at"),
                "rate_limit_reset_at": a.get("rate_limit_reset_at"),
                "overload_until": a.get("overload_until"),
                "last_used_at": a.get("last_used_at"),
                "groups": gnames,
                "problem": _account_problem(a),
            })
        # 有问题的排前面
        rows.sort(key=lambda r: (not r["problem"], str(r.get("platform") or ""), str(r.get("name") or "")))
        res.update({"ok": True, "summary": summary, "accounts": rows, "count": len(rows)})
        return res

    stations = await _fanout_sites(one)
    return {"ok": True, "stations": stations, "server_time": datetime.now().isoformat(timespec="seconds")}


# ---------------- 用户经济看板 ----------------
@app.get("/usereconomy")
async def usereconomy_page(request: Request):
    return templates.TemplateResponse("usereconomy.html", {"request": request})


@app.post("/api/user-economy")
async def post_user_economy(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return {"ok": False, "error": "请求体必须是 JSON"}
    name = str((payload or {}).get("site", "")).strip()
    site = await _find_site(name)
    if not site or not site["base_url"]:
        return {"ok": False, "error": f"未找到站点: {name}"}
    low_thr = _gnum((payload or {}).get("low_balance", 5))
    churn_days = int(_gnum((payload or {}).get("churn_days", 14)) or 14)
    new_days = int(_gnum((payload or {}).get("new_days", 7)) or 7)

    async with httpx.AsyncClient(timeout=40) as client:
        try:
            jwt = await _login(client, site["base_url"], site["email"], site["password"])
        except Exception as e:
            return {"ok": False, "error": str(e)}
        users = await _get_all_pages(client, site["base_url"], jwt, "/api/v1/admin/users", {})
        # 消费排行（近30天）
        today = date.today()
        ok, rank = await _get_json(
            client, site["base_url"], jwt, "/api/v1/admin/dashboard/users-ranking",
            {"start_date": (today - timedelta(days=29)).isoformat(), "end_date": today.isoformat(), "timezone": "Asia/Shanghai"},
        )
        ranking = (rank.get("ranking") if ok and isinstance(rank, dict) else []) or []

    now = datetime.now()
    def _parse(ts):
        if not ts:
            return None
        try:
            return datetime.fromisoformat(str(ts).replace("Z", "").split(".")[0].replace("T", " "))
        except ValueError:
            return None

    total_balance = 0.0
    total_recharged = 0.0
    low_list, churn_list, new_list = [], [], []
    for u in users:
        if not isinstance(u, dict):
            continue
        bal = _gnum(u.get("balance"))
        total_balance += bal
        total_recharged += _gnum(u.get("total_recharged"))
        email = u.get("email") or u.get("username") or str(u.get("id"))
        la = _parse(u.get("last_active_at") or u.get("last_used_at"))
        ca = _parse(u.get("created_at"))
        if bal <= low_thr:
            low_list.append({"email": email, "balance": round(bal, 4)})
        if bal > 0 and la is not None and (now - la).days >= churn_days:
            churn_list.append({"email": email, "balance": round(bal, 4), "last_active": u.get("last_active_at") or u.get("last_used_at")})
        if ca is not None and (now - ca).days <= new_days:
            new_list.append({"email": email, "created_at": u.get("created_at"), "total_recharged": round(_gnum(u.get("total_recharged")), 4)})
    low_list.sort(key=lambda x: x["balance"])
    churn_list.sort(key=lambda x: -x["balance"])
    new_list.sort(key=lambda x: str(x["created_at"]), reverse=True)
    top_spend = [{"email": r.get("email"), "actual_cost": round(_gnum(r.get("actual_cost")), 4),
                  "requests": _gnum(r.get("requests")), "tokens": _gnum(r.get("tokens"))} for r in ranking[:20]]

    return {
        "ok": True,
        "site": site["name"],
        "summary": {
            "total_users": len(users),
            "total_balance": round(total_balance, 2),
            "total_recharged": round(total_recharged, 2),
            "low_count": len(low_list),
            "churn_count": len(churn_list),
            "new_count": len(new_list),
        },
        "low_balance": low_list[:50],
        "churn": churn_list[:50],
        "new_users": new_list[:50],
        "top_spend": top_spend,
        "params": {"low_balance": low_thr, "churn_days": churn_days, "new_days": new_days},
        "server_time": datetime.now().isoformat(timespec="seconds"),
    }


# ---------------- 充值/收入报表 ----------------
@app.get("/revenuereport")
async def revenuereport_page(request: Request):
    return templates.TemplateResponse(
        "revenuereport.html",
        {"request": request, "today": date.today().isoformat(),
         "week_ago": (date.today() - timedelta(days=6)).isoformat()},
    )


@app.post("/api/revenue")
async def post_revenue(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return {"ok": False, "error": "请求体必须是 JSON"}
    start = str((payload or {}).get("start", "")).strip()
    end = str((payload or {}).get("end", "")).strip()
    if not start or not end:
        return {"ok": False, "error": "缺少时间段"}
    try:
        d0 = date.fromisoformat(start)
        d1 = date.fromisoformat(end)
    except ValueError:
        return {"ok": False, "error": "日期格式应为 YYYY-MM-DD"}
    if d1 < d0:
        d0, d1 = d1, d0

    def _used_day(ts):
        if not ts:
            return None
        s = str(ts).replace("T", " ")
        return s[:10] if len(s) >= 10 else None

    async def one(client, s):
        res = {"name": s["name"], "base_url": s["base_url"], "ok": False}
        if not s["base_url"]:
            res["error"] = "缺少站点地址"
            return res
        try:
            jwt = await _login(client, s["base_url"], s["email"], s["password"])
        except Exception as e:
            res["error"] = str(e)
            return res
        used = await _get_all_pages(client, s["base_url"], jwt, "/api/v1/admin/redeem-codes", {"status": "used"})
        ok_all, all_data = await _get_json(client, s["base_url"], jwt, "/api/v1/admin/redeem-codes", {"page": 1, "page_size": 1})
        total_codes = _gnum(all_data.get("total")) if ok_all and isinstance(all_data, dict) else 0
        by_day, by_type = {}, {}
        used_in_range = 0
        amount_total = 0.0
        for it in used:
            if not isinstance(it, dict):
                continue
            day = _used_day(it.get("used_at"))
            if not day or day < start or day > end:
                continue
            val = _gnum(it.get("value"))
            used_in_range += 1
            amount_total += val
            by_day[day] = by_day.get(day, 0.0) + val
            t = it.get("type") or "-"
            by_type[t] = by_type.get(t, 0.0) + val
        res.update({
            "ok": True,
            "amount_total": round(amount_total, 4),
            "used_in_range": used_in_range,
            "used_total": len(used),
            "total_codes": total_codes,
            "by_day": {k: round(v, 4) for k, v in by_day.items()},
            "by_type": {k: round(v, 4) for k, v in by_type.items()},
        })
        return res

    stations = await _fanout_sites(one, (payload or {}).get("names"))
    # 汇总按天
    all_days = [(d0 + timedelta(days=i)).isoformat() for i in range((d1 - d0).days + 1)]
    return {
        "ok": True,
        "start": start, "end": end, "days": all_days,
        "stations": stations,
        "server_time": datetime.now().isoformat(timespec="seconds"),
    }


# ---------------- 模型利润分解 ----------------
@app.get("/modelprofit")
async def modelprofit_page(request: Request):
    return templates.TemplateResponse(
        "modelprofit.html",
        {"request": request, "today": date.today().isoformat(),
         "week_ago": (date.today() - timedelta(days=6)).isoformat()},
    )


@app.post("/api/model-profit")
async def post_model_profit(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return {"ok": False, "error": "请求体必须是 JSON"}
    start = str((payload or {}).get("start", "")).strip()
    end = str((payload or {}).get("end", "")).strip()
    if not start or not end:
        return {"ok": False, "error": "缺少时间段"}
    try:
        date.fromisoformat(start)
        date.fromisoformat(end)
    except ValueError:
        return {"ok": False, "error": "日期格式应为 YYYY-MM-DD"}

    async def one(client, s):
        res = {"name": s["name"], "base_url": s["base_url"], "ok": False}
        if not s["base_url"]:
            res["error"] = "缺少站点地址"
            return res
        try:
            jwt = await _login(client, s["base_url"], s["email"], s["password"])
        except Exception as e:
            res["error"] = str(e)
            return res
        ok, data = await _get_json(
            client, s["base_url"], jwt, "/api/v1/admin/dashboard/models",
            {"start_date": start, "end_date": end, "timezone": "Asia/Shanghai"},
        )
        models = (data.get("models") if ok and isinstance(data, dict) else []) or []
        res.update({"ok": True, "models": [
            {
                "model": m.get("model"),
                "requests": _gnum(m.get("requests")),
                "tokens": _gnum(m.get("total_tokens")),
                "actual_cost": _gnum(m.get("actual_cost")),
                "account_cost": _gnum(m.get("account_cost")),
                "cost": _gnum(m.get("cost")),
            } for m in models if isinstance(m, dict)
        ]})
        return res

    stations = await _fanout_sites(one, (payload or {}).get("names"))
    # 跨站按模型汇总
    agg = {}
    for st in stations:
        if not st.get("ok"):
            continue
        for m in st.get("models", []):
            k = m["model"] or "-"
            a = agg.setdefault(k, {"model": k, "requests": 0.0, "tokens": 0.0, "actual_cost": 0.0, "account_cost": 0.0, "cost": 0.0})
            for f in ("requests", "tokens", "actual_cost", "account_cost", "cost"):
                a[f] += _gnum(m.get(f))
    models_agg = []
    for m in agg.values():
        margin = m["actual_cost"] - m["account_cost"]
        m["margin"] = round(margin, 4)
        m["margin_pct"] = round((margin / m["actual_cost"] * 100), 2) if m["actual_cost"] else 0
        for f in ("actual_cost", "account_cost", "cost"):
            m[f] = round(m[f], 4)
        models_agg.append(m)
    models_agg.sort(key=lambda x: -x["actual_cost"])
    return {"ok": True, "start": start, "end": end, "stations": stations, "models": models_agg,
            "server_time": datetime.now().isoformat(timespec="seconds")}


# ============================================================================
# 推送告警 + 钉钉 (DingTalk)
#   告警配置存 ALERTS_FILE(默认 /data/alerts.json，已 gitignore，不入库)。
#   含钉钉机器人 webhook + 加签 secret(可选) + 阈值规则 + 开关。
#   webhook/secret 不回显(只标 has_*)；保存时留空=不修改。
# ============================================================================
_alert_last_sent: dict[str, float] = {}
ALERT_COOLDOWN_S = 600  # 同一条告警 10 分钟内不重复推送

_DEFAULT_ALERT_RULES = {
    "sla_min": 98.0,            # SLA 低于此值(%)告警
    "error_rate_max": 3.0,      # 请求错误率高于此值(%)告警
    "upstream_rate_max": 5.0,   # 上游错误率高于此值(%)告警
    "normal_accounts_min": 1,   # 正常可用账号数低于此值告警
}


async def _load_alerts() -> dict:
    """告警配置已并入 PG settings['alerts']。"""
    data = await db.settings_get("alerts", {}) or {}
    if not isinstance(data, dict):
        data = {}
    dt = data.get("dingtalk") or {}
    rules = {**_DEFAULT_ALERT_RULES, **(data.get("rules") or {})}
    return {
        "enabled": bool(data.get("enabled", False)),
        "dingtalk": {"webhook": str(dt.get("webhook", "")), "secret": str(dt.get("secret", ""))},
        "rules": rules,
    }


async def _save_alerts(cfg: dict) -> None:
    await db.settings_set("alerts", cfg)


def _dingtalk_sign(secret: str, ts: str) -> str:
    string_to_sign = f"{ts}\n{secret}"
    digest = hmac.new(secret.encode("utf-8"), string_to_sign.encode("utf-8"), hashlib.sha256).digest()
    return urllib.parse.quote_plus(base64.b64encode(digest))


async def _dingtalk_send(client: httpx.AsyncClient, webhook: str, secret: str, text: str) -> tuple[bool, str]:
    if not webhook:
        return False, "未配置钉钉 webhook"
    url = webhook
    if secret:
        ts = str(round(time.time() * 1000))
        sign = _dingtalk_sign(secret, ts)
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}timestamp={ts}&sign={sign}"
    try:
        r = await client.post(url, json={"msgtype": "text", "text": {"content": text}}, timeout=15)
        j = r.json()
    except Exception as e:
        return False, f"请求钉钉失败: {e}"
    if j.get("errcode") == 0:
        return True, ""
    return False, j.get("errmsg") or str(j)


@app.get("/alertpush")
async def alertpush_page(request: Request):
    return templates.TemplateResponse("alertpush.html", {"request": request})


@app.get("/api/alert-config")
async def get_alert_config():
    cfg = await _load_alerts()
    dt = cfg["dingtalk"]
    return {
        "ok": True,
        "enabled": cfg["enabled"],
        "rules": cfg["rules"],
        "dingtalk": {"has_webhook": bool(dt["webhook"]), "has_secret": bool(dt["secret"])},
    }


@app.post("/api/alert-config")
async def post_alert_config(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return {"ok": False, "error": "请求体必须是 JSON"}
    if not isinstance(payload, dict):
        return {"ok": False, "error": "请求体格式错误"}
    cur = await _load_alerts()
    cur["enabled"] = bool(payload.get("enabled", cur["enabled"]))
    rules_in = payload.get("rules") or {}
    for k in _DEFAULT_ALERT_RULES:
        if k in rules_in:
            cur["rules"][k] = _gnum(rules_in[k])
    dt_in = payload.get("dingtalk") or {}
    # 留空=不改
    if str(dt_in.get("webhook", "")).strip():
        cur["dingtalk"]["webhook"] = str(dt_in["webhook"]).strip()
    if str(dt_in.get("secret", "")).strip():
        cur["dingtalk"]["secret"] = str(dt_in["secret"]).strip()
    try:
        await _save_alerts(cur)
    except Exception as e:
        return {"ok": False, "error": f"写入失败: {e}"}
    return {"ok": True}


@app.post("/api/alert-test")
async def post_alert_test(request: Request):
    cfg = await _load_alerts()
    dt = cfg["dingtalk"]
    async with httpx.AsyncClient() as client:
        ok, err = await _dingtalk_send(
            client, dt["webhook"], dt["secret"],
            f"【sub2report 测试】钉钉告警通道正常 · {datetime.now().isoformat(timespec='seconds')}",
        )
    return {"ok": ok} if ok else {"ok": False, "error": err}


async def _evaluate_alerts() -> list[str]:
    """跑一遍规则，返回触发的告警文案列表（不发送）。"""
    cfg = await _load_alerts()
    rules = cfg["rules"]
    msgs = []
    # SLA / 错误率：复用 ops overview
    sem = asyncio.Semaphore(OPS_MAX_PARALLEL)
    async with httpx.AsyncClient(timeout=25) as client:
        sites = await _load_sites()
        ops = await asyncio.gather(*[
            _fetch_station_ops(client, sem, s["name"], s["base_url"], s["email"], s["password"], "1h")
            for s in sites
        ], return_exceptions=True)
        for r in ops:
            if not isinstance(r, dict) or not r.get("ok"):
                continue
            m = r.get("metrics") or {}
            nm = r.get("name")
            sla = m.get("sla_percent")
            er = m.get("error_rate_percent")
            ur = m.get("upstream_error_rate_percent")
            if sla is not None and sla < rules["sla_min"]:
                msgs.append(f"[{nm}] SLA {sla:.2f}% < {rules['sla_min']}%")
            if er is not None and er > rules["error_rate_max"]:
                msgs.append(f"[{nm}] 请求错误率 {er:.2f}% > {rules['error_rate_max']}%")
            if ur is not None and ur > rules["upstream_rate_max"]:
                msgs.append(f"[{nm}] 上游错误率 {ur:.2f}% > {rules['upstream_rate_max']}%")
        # 账号池：用 stats normal_accounts
        async def _acct(s):
            try:
                jwt = await _login(client, s["base_url"], s["email"], s["password"])
                ok, data = await _get_json(client, s["base_url"], jwt, "/api/v1/admin/dashboard/stats")
                if ok and isinstance(data, dict):
                    return s["name"], _gnum(data.get("normal_accounts"))
            except Exception:
                pass
            return s["name"], None
        accts = await asyncio.gather(*[_acct(s) for s in sites])
        for nm, n in accts:
            if n is not None and n < rules["normal_accounts_min"]:
                msgs.append(f"[{nm}] 正常账号数 {int(n)} < {int(rules['normal_accounts_min'])}")
    return msgs


@app.post("/api/alert-check")
async def post_alert_check(request: Request):
    """立即检查（不一定发送）。?send=1 时把命中的告警推到钉钉。"""
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    send = bool((payload or {}).get("send"))
    msgs = await _evaluate_alerts()
    sent = False
    err = ""
    if send and msgs:
        cfg = await _load_alerts()
        async with httpx.AsyncClient() as client:
            ok, err = await _dingtalk_send(
                client, cfg["dingtalk"]["webhook"], cfg["dingtalk"]["secret"],
                "【sub2report 告警】\n" + "\n".join(msgs),
            )
            sent = ok
    return {"ok": True, "alerts": msgs, "count": len(msgs), "sent": sent, "error": err}


async def _alert_loop():
    """后台轮询：仅当 enabled 且配置了 webhook 时才检查并推送；带冷却去重。"""
    await asyncio.sleep(20)
    while True:
        try:
            cfg = await _load_alerts()
            if cfg["enabled"] and cfg["dingtalk"]["webhook"]:
                msgs = await _evaluate_alerts()
                now = time.time()
                fresh = [m for m in msgs if now - _alert_last_sent.get(m, 0) > ALERT_COOLDOWN_S]
                if fresh:
                    async with httpx.AsyncClient() as client:
                        ok, _ = await _dingtalk_send(
                            client, cfg["dingtalk"]["webhook"], cfg["dingtalk"]["secret"],
                            "【sub2report 告警】\n" + "\n".join(fresh),
                        )
                    if ok:
                        for m in fresh:
                            _alert_last_sent[m] = now
        except Exception:
            pass
        await asyncio.sleep(300)  # 每 5 分钟


@app.on_event("startup")
async def _start_alert_loop():
    asyncio.create_task(_alert_loop())


# ============================================================================
# 门户 + 后台管理（人员/角色/菜单/审计）。登录与权限由 auth.AuthMiddleware 统一拦截。
# ============================================================================
@app.get("/")
async def root_redirect(request: Request):
    return RedirectResponse(url="/portal", status_code=302)


@app.get("/portal")
async def portal_page(request: Request):
    user = auth.current_user(request)
    perms = request.state.perms
    menus = await db.menus_list()
    groups: dict[str, list] = {}
    for m in menus:
        if not m["enabled"]:
            continue
        if m["perm_code"] and m["perm_code"] not in perms:
            continue
        groups.setdefault(m["grp"] or "其它", []).append(m)
    # 保持分组顺序：报表 → 管理 → 其它
    order = ["报表", "管理", "其它"]
    grouped = [(g, groups[g]) for g in order if g in groups] + [(g, v) for g, v in groups.items() if g not in order]
    return templates.TemplateResponse("portal.html", {"request": request, "user": user, "grouped": grouped})


@app.get("/admin/users")
async def admin_users_page(request: Request):
    return templates.TemplateResponse("admin_users.html", {"request": request})


@app.get("/admin/roles")
async def admin_roles_page(request: Request):
    return templates.TemplateResponse("admin_roles.html", {"request": request})


@app.get("/admin/menus")
async def admin_menus_page(request: Request):
    return templates.TemplateResponse("admin_menus.html", {"request": request})


@app.get("/admin/audit")
async def admin_audit_page(request: Request):
    return templates.TemplateResponse("admin_audit.html", {"request": request})


# ---------------- 人员管理 API ----------------
@app.get("/api/admin/users")
async def api_users_list(request: Request):
    return {"ok": True, "users": await db.users_list(), "roles": await db.roles_list()}


@app.post("/api/admin/users")
async def api_users_create(request: Request):
    p = await request.json()
    email = str(p.get("email", "")).strip()
    pwd = str(p.get("password", ""))
    if not email or len(pwd) < 6:
        return {"ok": False, "error": "邮箱必填、密码至少 6 位"}
    if await db.user_by_email(email):
        return {"ok": False, "error": "邮箱已存在"}
    uid = await db.user_create(email, auth.hash_password(pwd), str(p.get("display_name", "")), [int(x) for x in (p.get("role_ids") or [])])
    await db.audit("user_create", user=auth.current_user(request), target=email, ip=auth.client_ip(request))
    return {"ok": True, "id": uid}


@app.put("/api/admin/users/{uid}")
async def api_users_update(uid: int, request: Request):
    p = await request.json()
    pwd_hash = auth.hash_password(p["password"]) if p.get("password") else None
    await db.user_update(
        uid,
        display_name=p.get("display_name"),
        status=p.get("status"),
        role_ids=[int(x) for x in p["role_ids"]] if p.get("role_ids") is not None else None,
        password_hash=pwd_hash,
    )
    await db.audit("user_update", user=auth.current_user(request), target=str(uid), ip=auth.client_ip(request))
    return {"ok": True}


@app.delete("/api/admin/users/{uid}")
async def api_users_delete(uid: int, request: Request):
    me = auth.current_user(request)
    if me and me["id"] == uid:
        return {"ok": False, "error": "不能删除自己"}
    await db.user_delete(uid)
    await db.audit("user_delete", user=me, target=str(uid), ip=auth.client_ip(request))
    return {"ok": True}


# ---------------- 角色管理 API ----------------
@app.get("/api/admin/roles")
async def api_roles_list(request: Request):
    return {"ok": True, "roles": await db.roles_list(), "permissions": await db.permissions_list()}


@app.post("/api/admin/roles")
async def api_roles_create(request: Request):
    p = await request.json()
    name = str(p.get("name", "")).strip()
    if not name:
        return {"ok": False, "error": "角色名必填"}
    rid = await db.role_create(name, str(p.get("description", "")), list(p.get("perms") or []))
    await db.audit("role_create", user=auth.current_user(request), target=name, ip=auth.client_ip(request))
    return {"ok": True, "id": rid}


@app.put("/api/admin/roles/{rid}")
async def api_roles_update(rid: int, request: Request):
    p = await request.json()
    await db.role_update(rid, name=p.get("name"), description=p.get("description"),
                         perm_codes=list(p["perms"]) if p.get("perms") is not None else None)
    await db.audit("role_update", user=auth.current_user(request), target=str(rid), ip=auth.client_ip(request))
    return {"ok": True}


@app.delete("/api/admin/roles/{rid}")
async def api_roles_delete(rid: int, request: Request):
    try:
        await db.role_delete(rid)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    await db.audit("role_delete", user=auth.current_user(request), target=str(rid), ip=auth.client_ip(request))
    return {"ok": True}


# ---------------- 菜单管理 API ----------------
@app.get("/api/admin/menus")
async def api_menus_list(request: Request):
    return {"ok": True, "menus": await db.menus_list(), "permissions": await db.permissions_list()}


@app.post("/api/admin/menus")
async def api_menus_create(request: Request):
    p = await request.json()
    if not str(p.get("title", "")).strip() or not str(p.get("path", "")).strip():
        return {"ok": False, "error": "标题和路径必填"}
    await db.menu_create(p["title"].strip(), p["path"].strip(), p.get("perm_code") or None, p.get("grp", ""), int(p.get("sort", 0) or 0))
    await db.audit("menu_create", user=auth.current_user(request), target=p.get("path", ""), ip=auth.client_ip(request))
    return {"ok": True}


@app.put("/api/admin/menus/{mid}")
async def api_menus_update(mid: int, request: Request):
    p = await request.json()
    await db.menu_update(mid, title=p.get("title"), path=p.get("path"), perm_code=p.get("perm_code"),
                         grp=p.get("grp"), sort=(int(p["sort"]) if p.get("sort") is not None else None),
                         enabled=p.get("enabled"))
    await db.audit("menu_update", user=auth.current_user(request), target=str(mid), ip=auth.client_ip(request))
    return {"ok": True}


@app.delete("/api/admin/menus/{mid}")
async def api_menus_delete(mid: int, request: Request):
    await db.menu_delete(mid)
    await db.audit("menu_delete", user=auth.current_user(request), target=str(mid), ip=auth.client_ip(request))
    return {"ok": True}


# ---------------- 审计日志 API ----------------
@app.get("/api/admin/audit")
async def api_audit_list(request: Request):
    rows = await db.audit_list(300)
    for r in rows:
        if r.get("ts"):
            r["ts"] = r["ts"].isoformat()
    return {"ok": True, "logs": rows}


# ---------------- 代理 IP 监测（只看 bar6 站，读 sub2api 已有的代理健康数据） ----------------
async def _bar6_site():
    for s in await db.sites_list():
        if "bar6" in (s["base_url"] or "").lower():
            return s
    return None


@app.get("/proxyhealth")
async def proxyhealth_page(request: Request):
    return templates.TemplateResponse("proxyhealth.html", {"request": request})


@app.get("/api/proxy-health")
async def api_proxy_health(request: Request):
    site = await _bar6_site()
    if not site or not site["base_url"]:
        return {"ok": False, "error": "未找到 bar6 站点（站点配置里需有 base_url 含 bar6 的站）"}
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            jwt = await _login(client, site["base_url"], site["email"], site["password"])
        except Exception as e:
            return {"ok": False, "error": f"登录失败: {e}"}
        proxies = await _get_all_pages(client, site["base_url"], jwt, "/api/v1/admin/proxies", {})
    rows = []
    for p in proxies:
        if not isinstance(p, dict):
            continue
        status = p.get("status")
        lat_status = p.get("latency_status")
        q_status = p.get("quality_status")
        problem = (status not in ("active", "enabled", None)) \
            or (lat_status not in ("success", None, "")) \
            or (q_status in ("fail", "error", "challenge"))
        rows.append({
            "id": p.get("id"), "name": p.get("name"), "protocol": p.get("protocol"),
            "host": p.get("host"), "port": p.get("port"), "status": status,
            "account_count": _gnum(p.get("account_count")),
            "latency_ms": p.get("latency_ms"), "latency_status": lat_status,
            "latency_message": p.get("latency_message"),
            "ip_address": p.get("ip_address"), "country": p.get("country"), "city": p.get("city"),
            "quality_status": q_status, "quality_score": p.get("quality_score"),
            "quality_grade": p.get("quality_grade"), "quality_summary": p.get("quality_summary"),
            "problem": problem,
        })
    rows.sort(key=lambda r: (not r["problem"], -(r["account_count"] or 0)))
    return {"ok": True, "site": site["name"], "base_url": site["base_url"], "proxies": rows,
            "count": len(rows), "problem_count": sum(1 for r in rows if r["problem"]),
            "server_time": datetime.now().isoformat(timespec="seconds")}


@app.post("/api/proxy-test")
async def api_proxy_test(request: Request):
    """手动触发 bar6 sub2api 对某个代理做一次延迟探测（sub2api 原生 test，轻量）。"""
    try:
        p = await request.json()
    except Exception:
        return {"ok": False, "error": "请求体必须是 JSON"}
    pid = p.get("id")
    if not pid:
        return {"ok": False, "error": "缺少代理 id"}
    site = await _bar6_site()
    if not site or not site["base_url"]:
        return {"ok": False, "error": "未找到 bar6 站点"}
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            jwt = await _login(client, site["base_url"], site["email"], site["password"])
        except Exception as e:
            return {"ok": False, "error": f"登录失败: {e}"}
        try:
            resp = await client.post(
                f"{site['base_url']}/api/v1/admin/proxies/{int(pid)}/test",
                headers={"Authorization": f"Bearer {jwt}"}, timeout=30,
            )
            body = resp.json()
            data = body.get("data", body) if isinstance(body, dict) else {}
        except Exception as e:
            return {"ok": False, "error": f"测试失败: {e}"}
    await db.audit("proxy_test", user=auth.current_user(request), target=f"bar6/proxy/{pid}", ip=auth.client_ip(request))
    return {"ok": True, "result": data if isinstance(data, dict) else {}}

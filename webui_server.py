
import asyncio
import time
from datetime import datetime, timedelta
from html import escape
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote_plus, urlparse

from astrbot.api import logger
try:
    from .webui_resources import STATUS_PANEL_TEMPLATE, WEBUI_STYLE
except ImportError:
    from webui_resources import STATUS_PANEL_TEMPLATE, WEBUI_STYLE

class PromptGuardianWebUI:
    def __init__(self, plugin: Any, host: str, port: int, session_timeout: int):
        self.plugin = plugin
        self.host = host
        self.port = port
        self.session_timeout = max(60, session_timeout)
        self._server: Optional[asyncio.AbstractServer] = None

    async def run(self):
        last_error: Optional[Exception] = None
        server_created = False
        original_port = self.port

        for offset in range(5):
            current_port = original_port + offset
            try:
                self._server = await asyncio.start_server(self._handle_client, self.host, current_port)
                if offset:
                    logger.warning(
                        f"WebUI 端口 {original_port} 已被占用，自动切换到 {current_port}。"
                    )
                    self.port = current_port
                    try:
                        self.plugin.config["webui_port"] = current_port
                        self.plugin.config.save_config()
                    except Exception as save_exc:
                        logger.warning(f"保存 WebUI 端口配置失败: {save_exc}")
                server_created = True
                break
            except OSError as exc:
                last_error = exc
                errno = getattr(exc, "errno", None)
                if errno in {98, 10013, 10048}:
                    logger.warning(f"WebUI 端口 {current_port} 已被占用，尝试 {current_port + 1} ...")
                    continue
                logger.error(f"AntiPromptInjector WebUI 启动失败: {exc}")
                return
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error(f"AntiPromptInjector WebUI 启动失败: {exc}")
                return

        if not server_created or not self._server:
            logger.error(f"AntiPromptInjector WebUI 启动失败: {last_error}")
            return

        try:
            sockets = self._server.sockets or []
            if sockets:
                address = sockets[0].getsockname()
                logger.info(f"🚀 AntiPromptInjector WebUI 已启动: http://{address[0]}:{address[1]}")
            await self._server.serve_forever()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error(f"AntiPromptInjector WebUI 运行异常: {exc}")
        finally:
            if self._server:
                self._server.close()
                await self._server.wait_closed()
                self._server = None

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            request_line = await reader.readline()
            if not request_line:
                return
            parts = request_line.decode("utf-8", "ignore").strip().split()
            if len(parts) != 3:
                writer.write(self._response(400, "Bad Request", "无法解析请求"))
                await writer.drain()
                return
            method, path, _ = parts
            headers: Dict[str, str] = {}
            while True:
                line = await reader.readline()
                if not line or line in (b"\r\n", b"\n"):
                    break
                key, _, value = line.decode("utf-8", "ignore").partition(":")
                headers[key.strip().lower()] = value.strip()
            body = b""
            if headers.get("content-length"):
                try:
                    length = int(headers["content-length"])
                    if length > 0:
                        body = await reader.readexactly(length)
                except Exception:
                    body = await reader.read(-1)
            cookies = self._parse_cookies(headers.get("cookie", ""))
            peer = writer.get_extra_info("peername")
            client_ip = peer[0] if isinstance(peer, tuple) and len(peer) > 0 else ""
            response = await self._dispatch(method, path, headers, body, cookies, client_ip)
            writer.write(response)
            await writer.drain()
        except Exception as exc:
            logger.error(f"WebUI 请求处理失败: {exc}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _parse_cookies(self, cookie_header: str) -> Dict[str, str]:
        if not cookie_header:
            return {}
        cookies: Dict[str, str] = {}
        for item in cookie_header.split(";"):
            if "=" in item:
                key, value = item.split("=", 1)
                cookies[key.strip()] = value.strip()
        return cookies

    def _authorized(self, cookies: Dict[str, str]) -> bool:
        self.plugin.prune_webui_sessions()
        session_id = cookies.get("API_SESSION")
        if not session_id:
            return False
        expiry = self.plugin.webui_sessions.get(session_id)
        if not expiry:
            return False
        if time.time() >= expiry:
            self.plugin.webui_sessions.pop(session_id, None)
            return False
        self.plugin.webui_sessions[session_id] = time.time() + self.session_timeout
        return True

    def _render_login_page(self, message: str = "", success: bool = True, password_ready: bool = True, token_param: str = "") -> str:
        status_class = "success" if success else "error"
        notice_html = f"<div class='notice {status_class}'>{escape(message)}</div>" if message else ""
        hint = ""
        if not password_ready:
            hint = (
                "<p class='danger-text login-footnote'>"
                "管理员尚未设置 WebUI 密码，请在 AstrBot 中发送指令 "
                "<code>/设置WebUI密码 &lt;新密码&gt;</code> 后再尝试登录。"
                "</p>"
            )
        disabled_attr = "disabled" if not password_ready else ""

        head_script = [
            "<script>",
            "(function(){",
            "    try {",
            "        const stored = localStorage.getItem('api-theme');",
            "        const theme = stored === 'light' ? 'light' : 'dark';",
            "        document.documentElement.setAttribute('data-theme', theme);",
            "    } catch (err) {}",
            "})();",
            "</script>",
            "</head>",
        ]
        body_script = [
            "<script>",
            "(function(){",
            "    const root = document.documentElement;",
            "    const apply = (theme) => {",
            "        root.setAttribute('data-theme', theme);",
            "        try { localStorage.setItem('api-theme', theme); } catch (err) {}",
            "    };",
            "    try {",
            "        const stored = localStorage.getItem('api-theme');",
            "        apply(stored === 'light' ? 'light' : 'dark');",
            "    } catch (err) {",
            "        apply('dark');",
            "    }",
            "    const toggle = document.getElementById('themeToggle');",
            "    if (toggle) {",
            "        toggle.addEventListener('click', () => {",
            "            const next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';",
            "            apply(next);",
            "        });",
            "    }",
            "})();",
            "</script>",
        ]

        html_parts = [
            "<!DOCTYPE html>",
            "<html lang='zh-CN'>",
            "<head>",
            "<meta charset='UTF-8'>",
            "<title>AntiPromptInjector 登录</title>",
            "<style>",
            WEBUI_STYLE,
            "</style>",
        ]
        html_parts.extend(head_script)
        plugin_version = getattr(self.plugin, "plugin_version", "unknown")
        ptd_version = getattr(self.plugin, "ptd_version", "unknown")
        html_parts.extend([
            "</head>",
            "<body class='login-body'>",
            "    <div class='login-container'>",
            "        <div class='login-panel'>",
            "            <div class='login-header'>",
            "                <h1>AntiPromptInjector 控制台</h1>",
            "                <button class='theme-toggle' id='themeToggle' type='button'><span class='moon'>🌙</span><span class='sun'>☀️</span></button>",
            "            </div>",
            f"            <p class='muted'>版本：v{escape(str(plugin_version))} · PTD：v{escape(str(ptd_version))}</p>",
            "            <p class='muted'>请输入管理员设置的 WebUI 密码，以保护配置不被未授权访问。</p>",
            f"            {notice_html}",
            "            <form method='post' action='/login'>",
            "                <label for='password'>登录密码</label>",
            f"                <input id='password' type='password' name='password' required {disabled_attr}>",
            (f"                <input type='hidden' name='token' value='{escape(token_param)}'>" if token_param else ""),
            f"                <button class='btn' type='submit' {disabled_attr}>进入面板</button>",
            "            </form>",
            f"            {hint}",
            "        </div>",
            "    </div>",
        ])
        html_parts.extend(body_script)
        html_parts.extend([
            "</body>",
            "</html>",
        ])
        return "\n".join(html_parts)

    def _build_query(self, pairs: Dict[str, str]) -> str:
        parts: List[str] = []
        for k, v in pairs.items():
            if v is None:
                continue
            s = str(v)
            if not s:
                continue
            parts.append(f"{quote_plus(k)}={quote_plus(s)}")
        return "&".join(parts)

    def _filter_incidents(self, params: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        items = list(self.plugin.recent_incidents)
        def get(name: str) -> str:
            return (params.get(name, [""])[0] or "").strip()
        sender = get("fi_sender")
        group = get("fi_group")
        severity = get("fi_severity")
        trigger = get("fi_trigger")
        action = get("fi_action")
        keyword = get("fi_keyword")
        since_min = get("fi_since")
        since_ts = None
        try:
            m = int(since_min) if since_min else 0
            since_ts = time.time() - m * 60 if m > 0 else None
        except Exception:
            since_ts = None

        def match_str(val: Any, needle: str) -> bool:
            if not needle:
                return True
            return needle.lower() in str(val or "").lower()

        out: List[Dict[str, Any]] = []
        for it in items:
            if since_ts and float(it.get("time", 0)) < since_ts:
                continue
            if sender and not match_str(it.get("sender_id"), sender):
                continue
            if group and not match_str(it.get("group_id"), group):
                continue
            if severity and str(it.get("severity")) != severity:
                continue
            if trigger and not match_str(it.get("trigger"), trigger):
                continue
            if action and str(it.get("action_taken", "")) != action:
                continue
            if keyword and not (
                match_str(it.get("reason"), keyword) or match_str(it.get("prompt_preview"), keyword)
            ):
                continue
            out.append(it)
        return out

    def _filter_logs(self, params: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        items = list(self.plugin.analysis_logs)
        def get(name: str) -> str:
            return (params.get(name, [""])[0] or "").strip()
        result = get("fl_result")
        sender = get("fl_sender")
        group = get("fl_group")
        severity = get("fl_severity")
        trigger = get("fl_trigger")
        action = get("fl_action")
        persona_action = get("fl_persona_action")
        keyword = get("fl_keyword")
        since_min = get("fl_since")
        since_ts = None
        try:
            m = int(since_min) if since_min else 0
            since_ts = time.time() - m * 60 if m > 0 else None
        except Exception:
            since_ts = None

        def match_str(val: Any, needle: str) -> bool:
            if not needle:
                return True
            return needle.lower() in str(val or "").lower()

        out: List[Dict[str, Any]] = []
        for it in items:
            if since_ts and float(it.get("time", 0)) < since_ts:
                continue
            if result and str(it.get("result")) != result:
                continue
            if sender and not match_str(it.get("sender_id"), sender):
                continue
            if group and not match_str(it.get("group_id"), group):
                continue
            if severity and str(it.get("severity")) != severity:
                continue
            if trigger and not match_str(it.get("trigger"), trigger):
                continue
            if action and str(it.get("action_taken", "")) != action:
                continue
            if persona_action and str(it.get("persona_action", "")) != persona_action:
                continue
            if keyword and not (
                match_str(it.get("reason"), keyword) or match_str(it.get("prompt_preview"), keyword)
            ):
                continue
            out.append(it)
        return out

    def _csv_escape(self, v: Any) -> str:
        s = str(v if v is not None else "")
        if any(ch in s for ch in [',', '\n', '"']):
            s = '"' + s.replace('"', '""') + '"'
        return s
    
    async def _dispatch(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        body: bytes,
        cookies: Dict[str, str],
        client_ip: str,
    ) -> bytes:
        import hmac # Imported here to ensure it's available
        parsed = urlparse(path)
        params = parse_qs(parsed.query)
        password_ready = self.plugin.is_password_configured()

        token_conf = str(self.plugin.config.get("webui_token", "") or "")
        token_ok = True
        token_val = ""
        if token_conf:
            if method == "GET":
                token_val = (params.get("token", [""])[0] or "").strip()
            elif method == "POST":
                try:
                    form_probe = parse_qs(body.decode("utf-8", "ignore"))
                    token_val = (form_probe.get("token", [""])[0] or "").strip()
                except Exception:
                    token_val = ""
            token_ok = bool(token_val and hmac.compare_digest(token_conf, token_val))

        if parsed.path != "/login":
            if token_conf and not token_ok:
                return self._response(403, "Forbidden", "需要有效令牌")

        if parsed.path == "/login":
            if method == "POST":
                if not password_ready:
                    return self._response(
                        200,
                        "OK",
                        self._render_login_page("尚未设置 WebUI 密码，请先通过指令配置。", success=False, password_ready=False),
                    )
                form = parse_qs(body.decode("utf-8", "ignore"))
                if token_conf and not hmac.compare_digest(token_conf, (form.get("token", [""])[0] or "").strip()):
                    return self._response(403, "Forbidden", "需要有效令牌")
                if not self.plugin.can_attempt_login(client_ip):
                    return self._response(
                        200,
                        "OK",
                        self._render_login_page("尝试次数过多，请稍后再试。", success=False, password_ready=True),
                    )
                password = form.get("password", [""])[0]
                if self.plugin.verify_webui_password(password):
                    session_id = self.plugin.create_webui_session(self.session_timeout)
                    headers = {
                        "Set-Cookie": self._make_session_cookie(session_id),
                    }
                    self.plugin.reset_login_attempts(client_ip)
                    return self._redirect_response(self._build_redirect_path("", "", True), extra_headers=headers)
                self.plugin.record_failed_login(client_ip)
                return self._response(
                    200,
                    "OK",
                    self._render_login_page("密码错误，请重试。", success=False, password_ready=True),
                )
            else:
                message = params.get("message", [""])[0]
                error_flag = params.get("error", ["0"])[0] == "1"
                token_param = (params.get("token", [""])[0] or "")
                return self._response(
                    200,
                    "OK",
                    self._render_login_page(message, success=not error_flag, password_ready=password_ready, token_param=token_param),
                )

        if method not in {"GET", "POST"}:
            return self._response(405, "Method Not Allowed", "仅支持 GET/POST 请求")

        if parsed.path == "/logout":
            session_id = cookies.get("API_SESSION")
            if session_id:
                self.plugin.webui_sessions.pop(session_id, None)
            headers = {"Set-Cookie": self._make_session_cookie("", expires=0)}
            return self._redirect_response("/login", extra_headers=headers)

        # Export endpoints (authorized only)
        if parsed.path.startswith("/export/"):
            if not password_ready:
                return self._redirect_response("/login?error=1&message=" + quote_plus("尚未设置密码"))
            if not self._authorized(cookies):
                return self._redirect_response("/login")

            if parsed.path == "/export/incidents.csv":
                rows = self._filter_incidents(params)
                fields = [
                    "time","sender_id","group_id","severity","score","trigger","defense_mode","action_taken","reason","prompt_preview"
                ]
                out = [",".join(fields)]
                for r in rows:
                    line = [self._csv_escape(r.get(f)) for f in fields]
                    out.append(",".join(line))
                csv_data = "\n".join(out)
                return self._response(
                    200,
                    "OK",
                    csv_data,
                    content_type="text/csv; charset=utf-8",
                    extra_headers={"Content-Disposition": "attachment; filename=incidents.csv"},
                )
            if parsed.path == "/export/analysis.csv":
                rows = self._filter_logs(params)
                fields = [
                    "time","sender_id","group_id","result","severity","score","trigger","core_version",
                    "action_taken","persona_action","persona_score","persona_reason","reason","prompt_preview"
                ]
                out = [",".join(fields)]
                for r in rows:
                    line = [self._csv_escape(r.get(f)) for f in fields]
                    out.append(",".join(line))
                csv_data = "\n".join(out)
                return self._response(
                    200,
                    "OK",
                    csv_data,
                    content_type="text/csv; charset=utf-8",
                    extra_headers={"Content-Disposition": "attachment; filename=analysis.csv"},
                )

        authorized = self._authorized(cookies)

        if not password_ready:
            return self._response(
                200,
                "OK",
                self._render_login_page("尚未设置 WebUI 密码，请通过指令 /设置WebUI密码 <新密码> 设置后再访问。", success=False, password_ready=False),
            )

        if not authorized:
            return self._redirect_response("/login")

        if method == "POST" and parsed.path == "/":
            origin = headers.get("origin") or headers.get("referer") or ""
            allowed = f"http://{self.host}:{self.port}"
            if origin and not origin.startswith(allowed):
                return self._response(403, "Forbidden", "来源不被允许")
            form = parse_qs(body.decode("utf-8", "ignore"))
            csrf = (form.get("csrf", [""])[0] or "").strip()
            session_id = cookies.get("API_SESSION", "")
            if not self.plugin.verify_csrf(session_id, csrf):
                return self._response(403, "Forbidden", "CSRF 校验失败")
            action = (form.get("action", [None])[0] or None)
            if action:
                message, success = await self._apply_action(action, form)
                redirect_path = self._build_redirect_path("", message, success)
                return self._redirect_response(redirect_path)
        notice = params.get("notice", [""])[0]
        success_flag = params.get("success", ["1"])[0] == "1"
        session_id = cookies.get("API_SESSION", "")
        html = self._render_dashboard(notice, success_flag, params, session_id)
        return self._response(200, "OK", html, content_type="text/html; charset=utf-8")

    async def _apply_action(self, action: str, params: Dict[str, List[str]]) -> Tuple[str, bool]:
        config = self.plugin.config
        message = ""
        success = True

        def save():
            config.save_config()
            self.plugin._update_incident_capacity()

        try:
            if action == "toggle_enabled":
                value = params.get("value", ["off"])[0]
                enabled = value != "off"
                config["enabled"] = enabled
                save()
                message = "插件已开启" if enabled else "插件已关闭"
            elif action == "set_defense_mode":
                value = params.get("value", ["strict"])[0]
                if value not in {"passive", "standard", "aggressive", "strict"}:
                    return "无效的防护模式", False
                config["defense_mode"] = value
                save()
                message = f"防护模式已切换为 {value}"
            elif action == "set_llm_mode":
                value = params.get("value", ["standby"])[0]
                if value not in {"active", "standby", "disabled"}:
                    return "无效的 LLM 模式", False
                config["llm_analysis_mode"] = value
                if value != "active":
                    self.plugin.last_llm_analysis_time = None
                save()
                message = f"LLM 辅助模式已切换为 {value}"
            elif action == "toggle_auto_blacklist":
                enabled = not config.get("auto_blacklist", True)
                config["auto_blacklist"] = enabled
                save()
                message = "自动拉黑已开启" if enabled else "自动拉黑已关闭"
            elif action == "toggle_private_llm":
                enabled = not config.get("llm_analysis_private_chat_enabled", False)
                config["llm_analysis_private_chat_enabled"] = enabled
                save()
                message = "私聊 LLM 分析已开启" if enabled else "私聊 LLM 分析已关闭"
            elif action == "toggle_anti_harassment":
                enabled = not bool(config.get("anti_harassment_enabled", True))
                config["anti_harassment_enabled"] = enabled
                save()
                message = "防骚扰检测已开启" if enabled else "防骚扰检测已关闭"
            elif action == "set_review_options":
                rp = params.get("review_provider", [""])[0].strip()
                rm = params.get("review_model", [""])[0].strip()
                config["review_provider"] = rp
                config["review_model"] = rm
                save()
                rp_disp = rp if rp else "默认"
                rm_disp = rm if rm else "默认"
                message = f"审查供应商/模型已更新为：{rp_disp} / {rm_disp}"
            elif action == "add_whitelist":
                target = params.get("target", [""])[0].strip()
                if not target:
                    return "需要提供用户 ID", False
                whitelist = config.get("whitelist", [])
                if target in whitelist:
                    return "该用户已在白名单", False
                whitelist.append(target)
                config["whitelist"] = whitelist
                save()
                message = f"{target} 已加入白名单"
            elif action == "remove_whitelist":
                target = params.get("target", [""])[0].strip()
                whitelist = config.get("whitelist", [])
                if target not in whitelist:
                    return "用户不在白名单", False
                whitelist.remove(target)
                config["whitelist"] = whitelist
                save()
                message = f"{target} 已移出白名单"
            elif action == "add_blacklist":
                target = params.get("target", [""])[0].strip()
                duration_str = params.get("duration", ["60"])[0].strip()
                if not target:
                    return "需要提供用户 ID", False
                try:
                    duration = int(duration_str)
                except ValueError:
                    return "封禁时长必须是数字", False
                blacklist = config.get("blacklist", {})
                if duration <= 0:
                    blacklist[target] = float("inf")
                else:
                    blacklist[target] = time.time() + duration * 60
                config["blacklist"] = blacklist
                save()
                message = f"{target} 已加入黑名单"
            elif action == "remove_blacklist":
                target = params.get("target", [""])[0].strip()
                blacklist = config.get("blacklist", {})
                if target not in blacklist:
                    return "用户不在黑名单", False
                del blacklist[target]
                config["blacklist"] = blacklist
                save()
                message = f"{target} 已移出黑名单"
            elif action == "clear_history":
                self.plugin.recent_incidents.clear()
                message = "已清空拦截记录"
            elif action == "clear_logs":
                self.plugin.analysis_logs.clear()
                message = "已清空分析日志"
            else:
                message = "未知操作"
                success = False
        except Exception as exc:
            logger.error(f"WebUI 动作执行失败: {exc}")
            return "内部错误，请检查日志。", False
        return message, success

    def _render_dashboard(self, notice: str, success: bool, params: Optional[Dict[str, List[str]]] = None, session_id: str = "") -> str:
        config = self.plugin.config
        stats = self.plugin.stats
        incidents = self._filter_incidents(params or {})
        analysis_logs = self._filter_logs(params or {})
        whitelist = config.get("whitelist", [])
        blacklist = config.get("blacklist", {})
        defense_mode = config.get("defense_mode", "sentry")
        llm_mode = config.get("llm_analysis_mode", "standby")
        private_llm = config.get("llm_analysis_private_chat_enabled", False)
        auto_blacklist = config.get("auto_blacklist", True)
        enabled = config.get("enabled", True)
        anti_harassment = bool(config.get("anti_harassment_enabled", True))
        review_provider = str(config.get("review_provider", "") or "")
        review_model = str(config.get("review_model", "") or "")
        ptd_version = getattr(self.plugin, "ptd_version", "unknown")
        plugin_version = getattr(self.plugin, "plugin_version", "unknown")

        defense_labels = {
            "passive": "观察模式",
            "standard": "标准模式",
            "strict": "严格模式",
            "aggressive": "激进模式",
        }
        llm_labels = {
            "active": "活跃",
            "standby": "待机",
            "disabled": "禁用",
        }

        html_parts = [
            "<!DOCTYPE html>",
            "<html lang='zh-CN'>",
            "<head>",
            "<meta charset='UTF-8'>",
            "<title>AntiPromptInjector 控制台</title>",
            "<style>",
            WEBUI_STYLE,
            "</style>",
            "<script>",
            "(function(){",
            "    try {",
            "        const stored = localStorage.getItem('api-theme');",
            "        const theme = stored === 'light' ? 'light' : 'dark';",
            "        document.documentElement.setAttribute('data-theme', theme);",
            "    } catch (err) {}",
            "})();",
            "</script>",
            "</head>",
            "<body>",
            "<div class='container'>",
            "<header><h1>AntiPromptInjector 控制台</h1><div class='header-actions'><button class='theme-toggle' id='themeToggle' type='button'><span class='moon'>🌙</span><span class='sun'>☀️</span></button><a class='logout-link' href='/logout'>退出登录</a></div></header>",
        ]

        if notice:
            notice_class = "success" if success else "error"
            html_parts.append(f"<div class='notice {notice_class}'>{escape(notice)}</div>")

        html_parts.append("<div class='card-grid'>")

        status_lines = [
            f"插件状态：{'🟢 已启用' if enabled else '🟥 已停用'}",
            f"插件版本：v{escape(str(plugin_version))}",
            f"PTD 核心：v{escape(str(ptd_version))}",
            f"防护模式：{defense_labels.get(defense_mode, defense_mode)}",
            f"LLM 辅助策略：{llm_labels.get(llm_mode, llm_mode)}",
            f"自动拉黑：{'开启' if auto_blacklist else '关闭'}",
            f"私聊 LLM 分析：{'开启' if private_llm else '关闭'}",
            f"防骚扰检测：{'开启' if anti_harassment else '关闭'}",
            f"审查供应商：{escape(review_provider) if review_provider else '默认'}",
            f"审查模型：{escape(review_model) if review_model else '默认'}",
        ]
        html_parts.append("<div class='card'><h3>安全总览</h3>")
        for line in status_lines:
            html_parts.append(f"<p>{line}</p>")
        html_parts.append("</div>")

        html_parts.append("<div class='card'><h3>拦截统计</h3>")
        html_parts.append(f"<p>总拦截次数：{stats.get('total_intercepts', 0)}</p>")
        html_parts.append(f"<p>正则/特征命中：{stats.get('regex_hits', 0)}</p>")
        html_parts.append(f"<p>启发式判定：{stats.get('heuristic_hits', 0)}</p>")
        html_parts.append(f"<p>LLM 判定：{stats.get('llm_hits', 0)}</p>")
        html_parts.append(f"<p>自动拉黑次数：{stats.get('auto_blocked', 0)}</p>")
        html_parts.append("</div>")

        toggle_label = "关闭防护" if enabled else "开启防护"
        toggle_value = "off" if enabled else "on"
        html_parts.append("<div class='card'><h3>快速操作</h3><div class='actions'>")
        tkn = str(config.get("webui_token", "") or "")
        csrf_token = self.plugin.get_csrf_token(session_id)
        token_field = f"<input type='hidden' name='token' value='{escape(tkn)}'/>" if tkn else ""
        html_parts.append(
            "<form class='inline-form' method='post' action='/'>"
            "<input type='hidden' name='action' value='toggle_enabled'/>"
            f"<input type='hidden' name='value' value='{toggle_value}'/>"
            f"<input type='hidden' name='csrf' value='{escape(csrf_token)}'/>"
            f"{token_field}"
            f"<button class='btn' type='submit'>{toggle_label}</button></form>"
        )
        for mode in ("passive", "standard", "aggressive", "strict"):
            html_parts.append(
                "<form class='inline-form' method='post' action='/'>"
                "<input type='hidden' name='action' value='set_defense_mode'/>"
                f"<input type='hidden' name='value' value='{mode}'/>"
                f"<input type='hidden' name='csrf' value='{escape(csrf_token)}'/>"
            f"{token_field}"
                f"<button class='btn secondary' type='submit'>{defense_labels[mode]}</button></form>"
            )
        for mode in ("active", "standby", "disabled"):
            html_parts.append(
                "<form class='inline-form' method='post' action='/'>"
                "<input type='hidden' name='action' value='set_llm_mode'/>"
                f"<input type='hidden' name='value' value='{mode}'/>"
                f"<input type='hidden' name='csrf' value='{escape(csrf_token)}'/>"
            f"{token_field}"
                f"<button class='btn secondary' type='submit'>LLM {llm_labels[mode]}</button></form>"
            )
        html_parts.append(
            "<form class='inline-form' method='post' action='/'>"
            "<input type='hidden' name='action' value='toggle_auto_blacklist'/>"
            f"<input type='hidden' name='csrf' value='{escape(csrf_token)}'/>"
            f"{token_field}"
            f"<button class='btn secondary' type='submit'>{'关闭自动拉黑' if auto_blacklist else '开启自动拉黑'}</button></form>"
        )
        html_parts.append(
            "<form class='inline-form' method='post' action='/'>"
            "<input type='hidden' name='action' value='toggle_private_llm'/>"
            f"<input type='hidden' name='csrf' value='{escape(csrf_token)}'/>"
            f"{token_field}"
            f"<button class='btn secondary' type='submit'>{'关闭私聊分析' if private_llm else '开启私聊分析'}</button></form>"
        )
        html_parts.append(
            "<form class='inline-form' method='post' action='/'>"
            "<input type='hidden' name='action' value='toggle_anti_harassment'/>"
            f"<input type='hidden' name='csrf' value='{escape(csrf_token)}'/>"
            f"{token_field}"
            f"<button class='btn secondary' type='submit'>{'关闭防骚扰' if anti_harassment else '开启防骚扰'}</button></form>"
        )
        html_parts.append(
            "<form class='inline-form' method='post' action='/'>"
            "<input type='hidden' name='action' value='set_review_options'/>"
            f"<input type='text' name='review_provider' placeholder='审查供应商' value='{escape(review_provider)}'/>"
            f"<input type='text' name='review_model' placeholder='审查模型' value='{escape(review_model)}'/>"
            f"<input type='hidden' name='csrf' value='{escape(csrf_token)}'/>"
            f"{token_field}"
            "<button class='btn secondary' type='submit'>保存审查配置</button>"
            "</form>"
        )
        html_parts.append(
            "<form class='inline-form' method='post' action='/'>"
            "<input type='hidden' name='action' value='clear_history'/>"
            f"<input type='hidden' name='csrf' value='{escape(csrf_token)}'/>"
            f"{token_field}"
            "<button class='btn danger' type='submit'>清空拦截记录</button></form>"
        )
        html_parts.append(
            "<form class='inline-form' method='post' action='/'>"
            "<input type='hidden' name='action' value='clear_logs'/>"
            f"<input type='hidden' name='csrf' value='{escape(csrf_token)}'/>"
            f"{token_field}"
            "<button class='btn danger' type='submit'>清空分析日志</button></form>"
        )
        html_parts.append("</div></div>")
        html_parts.append("</div>")  # end card-grid

        # Filters & Export section
        def pv(name: str) -> str:
            if not params:
                return ""
            return escape((params.get(name, [""])[0] or ""))
        fi_fields = ["fi_sender","fi_group","fi_severity","fi_trigger","fi_action","fi_keyword","fi_since"]
        fl_fields = ["fl_result","fl_sender","fl_group","fl_severity","fl_trigger","fl_action","fl_persona_action","fl_keyword","fl_since"]
        fi_query = self._build_query({k: (params.get(k, [""])[0] if params else "") for k in fi_fields})
        fl_query = self._build_query({k: (params.get(k, [""])[0] if params else "") for k in fl_fields})
        html_parts.append("<section class='section-with-table'>")
        html_parts.append("<h3>筛选与导出</h3>")
        html_parts.append("<form method='get' action='/' class='inline-form'>")
        html_parts.append(f"<input type='text' name='fi_sender' placeholder='拦截·用户ID' value='{pv('fi_sender')}'/>")
        html_parts.append(f"<input type='text' name='fi_group' placeholder='拦截·群ID' value='{pv('fi_group')}'/>")
        html_parts.append(f"<input type='text' name='fi_severity' placeholder='拦截·严重级别' value='{pv('fi_severity')}'/>")
        html_parts.append(f"<input type='text' name='fi_trigger' placeholder='拦截·触发' value='{pv('fi_trigger')}'/>")
        html_parts.append(f"<input type='text' name='fi_action' placeholder='拦截·动作' value='{pv('fi_action')}'/>")
        html_parts.append(f"<input type='text' name='fi_keyword' placeholder='拦截·关键词(原因/预览)' value='{pv('fi_keyword')}'/>")
        html_parts.append(f"<input type='number' name='fi_since' placeholder='拦截·分钟' min='0' value='{pv('fi_since')}'/>")
        html_parts.append("<br/>")
        html_parts.append(f"<input type='text' name='fl_result' placeholder='分析·结果' value='{pv('fl_result')}'/>")
        html_parts.append(f"<input type='text' name='fl_sender' placeholder='分析·用户ID' value='{pv('fl_sender')}'/>")
        html_parts.append(f"<input type='text' name='fl_group' placeholder='分析·群ID' value='{pv('fl_group')}'/>")
        html_parts.append(f"<input type='text' name='fl_severity' placeholder='分析·严重级别' value='{pv('fl_severity')}'/>")
        html_parts.append(f"<input type='text' name='fl_trigger' placeholder='分析·触发' value='{pv('fl_trigger')}'/>")
        html_parts.append(f"<input type='text' name='fl_action' placeholder='分析·动作' value='{pv('fl_action')}'/>")
        html_parts.append(f"<input type='text' name='fl_persona_action' placeholder='分析·人设动作' value='{pv('fl_persona_action')}'/>")
        html_parts.append(f"<input type='text' name='fl_keyword' placeholder='分析·关键词(原因/预览)' value='{pv('fl_keyword')}'/>")
        html_parts.append(f"<input type='number' name='fl_since' placeholder='分析·分钟' min='0' value='{pv('fl_since')}'/>")
        html_parts.append("<div class='actions'>")
        html_parts.append("<button class='btn' type='submit'>应用筛选</button>")
        html_parts.append("<a class='btn secondary' href='/'>清除筛选</a>")
        if tkn:
            fi_query = (fi_query + ("&" if fi_query else "")) + f"token={quote_plus(tkn)}"
            fl_query = (fl_query + ("&" if fl_query else "")) + f"token={quote_plus(tkn)}"
        html_parts.append(f"<a class='btn secondary' href='/export/incidents.csv?{fi_query}'>导出拦截CSV</a>")
        html_parts.append(f"<a class='btn secondary' href='/export/analysis.csv?{fl_query}'>导出分析CSV</a>")
        html_parts.append("</div>")
        html_parts.append(f"<p class='small'>拦截事件：{len(incidents)} 条 · 分析日志：{len(analysis_logs)} 条</p>")
        html_parts.append("</form>")
        html_parts.append("</section>")

        html_parts.append("<div class='dual-column'>")
        html_parts.append("<div class='section-with-table'><h3>白名单</h3>")
        if whitelist:
            html_parts.append("<table><thead><tr><th>用户</th></tr></thead><tbody>")
            for uid in whitelist[:100]:
                html_parts.append(f"<tr><td>{escape(uid)}</td></tr>")
            html_parts.append("</tbody></table>")
        else:
            html_parts.append("<p class='muted'>当前白名单为空。</p>")
        html_parts.append(
            "<div class='actions'>"
            "<form class='inline-form' method='post' action='/'>"
            "<input type='hidden' name='action' value='add_whitelist'/>"
            "<input type='text' name='target' placeholder='用户 ID'/>"
            f"<input type='hidden' name='csrf' value='{escape(csrf_token)}'/>"
            f"{token_field}"
            "<button class='btn secondary' type='submit'>添加白名单</button></form>"
            "<form class='inline-form' method='post' action='/'>"
            "<input type='hidden' name='action' value='remove_whitelist'/>"
            "<input type='text' name='target' placeholder='用户 ID'/>"
            f"<input type='hidden' name='csrf' value='{escape(csrf_token)}'/>"
            f"{token_field}"
            "<button class='btn secondary' type='submit'>移除白名单</button></form>"
            "</div>"
        )
        html_parts.append("</div>")

        html_parts.append("<div class='section-with-table'><h3>黑名单</h3>")
        if blacklist:
            html_parts.append("<table><thead><tr><th>用户</th><th>剩余时间</th></tr></thead><tbody>")
            now = time.time()
            for uid, expiry in list(blacklist.items())[:100]:
                if expiry == float("inf"):
                    remain = "永久"
                else:
                    seconds = max(0, int(expiry - now))
                    remain = str(timedelta(seconds=seconds))
                html_parts.append(f"<tr><td>{escape(str(uid))}</td><td>{escape(remain)}</td></tr>")
            html_parts.append("</tbody></table>")
        else:
            html_parts.append("<p class='muted'>当前黑名单为空。</p>")
        html_parts.append(
            "<div class='actions'>"
            "<form class='inline-form' method='post' action='/'>"
            "<input type='hidden' name='action' value='add_blacklist'/>"
            "<input type='text' name='target' placeholder='用户 ID'/>"
            "<input type='number' name='duration' placeholder='分钟(0=永久)' min='0'/>"
            f"<input type='hidden' name='csrf' value='{escape(csrf_token)}'/>"
            f"{token_field}"
            "<button class='btn secondary' type='submit'>添加黑名单</button></form>"
            "<form class='inline-form' method='post' action='/'>"
            "<input type='hidden' name='action' value='remove_blacklist'/>"
            "<input type='text' name='target' placeholder='用户 ID'/>"
            f"<input type='hidden' name='csrf' value='{escape(csrf_token)}'/>"
            f"{token_field}"
            "<button class='btn secondary' type='submit'>移除黑名单</button></form>"
            "</div>"
        )
        html_parts.append("</div>")
        html_parts.append("</div>")  # end dual-column

        html_parts.append("<div class='dual-column'>")

        html_parts.append("<div class='section-with-table'><h3>拦截事件</h3>")
        if incidents:
            html_parts.append("<table><thead><tr><th>时间</th><th>来源</th><th>严重级别</th><th>得分</th><th>触发</th><th>原因</th><th>预览</th></tr></thead><tbody>")
            for item in incidents[:50]:
                timestamp = datetime.fromtimestamp(item["time"]).strftime("%Y-%m-%d %H:%M:%S")
                source = item["sender_id"]
                if item.get("group_id"):
                    source = f"{source} @ {item['group_id']}"
                html_parts.append(
                    "<tr>"
                    f"<td>{escape(timestamp)}</td>"
                    f"<td>{escape(str(source))}</td>"
                    f"<td>{escape(item.get('severity', ''))}</td>"
                    f"<td>{escape(str(item.get('score', 0)))}</td>"
                    f"<td>{escape(item.get('trigger', ''))}</td>"
                    f"<td>{escape(item.get('reason', ''))}</td>"
                    f"<td>{escape(item.get('prompt_preview', ''))}</td>"
                    "</tr>"
                )
            html_parts.append("</tbody></table>")
        else:
            html_parts.append("<p class='muted'>尚未记录拦截事件。</p>")
        html_parts.append("</div>")

        html_parts.append("<div class='section-with-table'><h3>分析日志</h3>")
        if analysis_logs:
            html_parts.append("<table class='analysis-table'><thead><tr><th>时间</th><th>来源</th><th>结果</th><th>严重级别</th><th>得分</th><th>触发</th><th>核心版本</th><th>原因</th><th>内容预览</th></tr></thead><tbody>")
            for item in analysis_logs[:50]:
                timestamp = datetime.fromtimestamp(item["time"]).strftime("%Y-%m-%d %H:%M:%S")
                source = item["sender_id"]
                if item.get("group_id"):
                    source = f"{source} @ {item['group_id']}"
                html_parts.append(
                    "<tr>"
                    f"<td>{escape(timestamp)}</td>"
                    f"<td>{escape(str(source))}</td>"
                    f"<td>{escape(item.get('result', ''))}</td>"
                    f"<td>{escape(item.get('severity', ''))}</td>"
                    f"<td>{escape(str(item.get('score', 0)))}</td>"
                    f"<td>{escape(item.get('trigger', ''))}</td>"
                    f"<td>{escape(str(item.get('core_version', '')))}</td>"
                    f"<td>{escape(item.get('reason', ''))}</td>"
                    f"<td>{escape(item.get('prompt_preview', ''))}</td>"
                    "</tr>"
                )
            html_parts.append("</tbody></table>")
        else:
            html_parts.append("<p class='muted'>暂无分析日志，可等待消息经过后查看。</p>")
        html_parts.append("</div>")

        html_parts.append("</div>")  # end dual-column

        html_parts.append("</div>")
        html_parts.append("<script>")
        html_parts.append("(function(){")
        html_parts.append("  const root = document.documentElement;")
        html_parts.append("  const apply = (theme) => {")
        html_parts.append("    root.setAttribute('data-theme', theme);")
        html_parts.append("    try { localStorage.setItem('api-theme', theme); } catch (err) {}")
        html_parts.append("  };")
        html_parts.append("  try {")
        html_parts.append("    const stored = localStorage.getItem('api-theme');")
        html_parts.append("    apply(stored === 'light' ? 'light' : 'dark');")
        html_parts.append("  } catch (err) {")
        html_parts.append("    apply('dark');")
        html_parts.append("  }")
        html_parts.append("  const toggle = document.getElementById('themeToggle');")
        html_parts.append("  if (toggle) {")
        html_parts.append("    toggle.addEventListener('click', () => {")
        html_parts.append("      const next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';")
        html_parts.append("      apply(next);")
        html_parts.append("    });")
        html_parts.append("  }")
        html_parts.append("})();")
        html_parts.append("</script>")
        html_parts.append("</body></html>")
        return "\n".join(html_parts)

    def _build_redirect_path(self, token: str, message: str, success: bool) -> str:
        query_parts = []
        if token:
            query_parts.append(f"token={quote_plus(token)}")
        if message:
            query_parts.append(f"notice={quote_plus(message)}")
            query_parts.append(f"success={'1' if success else '0'}")
        query = "&".join(query_parts)
        if not token and str(self.plugin.config.get("webui_token", "") or ""):
            query = (query + ("&" if query else "")) + f"token={quote_plus(str(self.plugin.config.get('webui_token', '') or ''))}"
        return "/?" + query if query else "/"

    def _response(self, status: int, reason: str, body: str, content_type: str = "text/html; charset=utf-8", extra_headers: Optional[Dict[str, str]] = None) -> bytes:
        body_bytes = body.encode("utf-8")
        headers = [
            f"HTTP/1.1 {status} {reason}",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body_bytes)}",
            "Connection: close",
            "Cache-Control: no-store",
            "X-Content-Type-Options: nosniff",
            "X-Frame-Options: DENY",
            "Referrer-Policy: no-referrer",
            "Content-Security-Policy: default-src 'none'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
        ]
        if extra_headers:
            for key, value in extra_headers.items():
                headers.append(f"{key}: {value}")
        headers.extend(["", ""])
        return "\r\n".join(headers).encode("utf-8") + body_bytes

    def _redirect_response(self, location: str, extra_headers: Optional[Dict[str, str]] = None) -> bytes:
        headers = [
            "HTTP/1.1 302 Found",
            f"Location: {location}",
            "Content-Length: 0",
            "Connection: close",
        ]
        if extra_headers:
            for key, value in extra_headers.items():
                headers.append(f"{key}: {value}")
        headers.extend(["", ""])
        return "\r\n".join(headers).encode("utf-8")

    def _make_session_cookie(self, session_id: str, expires: Optional[int] = None) -> str:
        if not session_id:
            return "API_SESSION=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
        max_age = expires if expires is not None else self.session_timeout
        return f"API_SESSION={session_id}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}"

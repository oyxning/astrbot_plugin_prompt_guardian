
STATUS_PANEL_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@700&family=Noto+Sans+SC:wght@300;400;700&display=swap');
    body { font-family: 'Noto Sans SC', sans-serif; background: #1a1b26; color: #a9b1d6; margin: 0; padding: 24px; display: flex; justify-content: center; align-items: center; }
    .panel { width: 720px; background: rgba(36, 40, 59, 0.85); border: 1px solid #3b4261; border-radius: 16px; box-shadow: 0 0 32px rgba(125, 207, 255, 0.25); backdrop-filter: blur(12px); padding: 36px; }
    .header { display: flex; align-items: center; border-bottom: 1.5px solid #3b4261; padding-bottom: 20px; margin-bottom: 28px; }
    .header-icon { font-size: 44px; margin-right: 22px; animation: pulse 2s infinite; }
    .header-title h1 { font-family: 'Orbitron', sans-serif; font-size: 32px; color: #bb9af7; margin: 0; letter-spacing: 3px; text-shadow: 0 0 14px #bb9af7; }
    .status-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 24px;}
    .full-width-block { grid-column: 1 / -1; }
    .status-block { background: #24283b; border-radius: 12px; padding: 28px; border: 1.5px solid #3b4261; }
    .status-block h2 { font-size: 20px; color: #7dcfff; margin: 0 0 16px 0; font-weight: 700; border-bottom: 1px solid #3b4261; padding-bottom: 10px; }
    .status-block .value { font-size: 28px; font-weight: 800; margin-bottom: 12px; }
    .status-block .description { font-size: 16px; color: #a9b1d6; line-height: 1.7; font-weight: 400; }
    .value.passive { color: #9ece6a; text-shadow: 0 0 10px #9ece6a;}
    .value.standard { color: #7dcfff; text-shadow: 0 0 10px #7dcfff;}
    .value.aggressive { color: #ff757f; text-shadow: 0 0 10px #ff757f;}
    .value.strict { color: #e0af68; text-shadow: 0 0 10px #e0af68;}
    .value.active { color: #9ece6a; }
    .value.standby { color: #e0af68; }
    .value.disabled { color: #565f89; }
    @keyframes pulse { 0% { transform: scale(1); opacity: 0.8; } 50% { transform: scale(1.1); opacity: 1; } 100% { transform: scale(1); opacity: 0.8; } }
</style>
</head>
<body>
    <div class="panel">
        <div class="header">
            <div class="header-icon">🛡️</div>
            <div class="header-title"><h1>INJECTION DEFENSE</h1></div>
        </div>
        <div class="status-block full-width-block">
            <h2>核心防御模式</h2>
            <p class="value {{ defense_mode_class }}">{{ defense_mode_name }}</p>
            <p class="description">{{ defense_mode_description }}</p>
        </div>
        <div class="status-grid">
            <div class="status-block">
                <h2>LLM分析 (群聊)</h2>
                <p class="value {{ mode_class }}">{{ current_mode }}</p>
                <p class="description">{{ mode_description }}</p>
            </div>
            <div class="status-block">
                <h2>LLM分析 (私聊)</h2>
                <p class="value {{ private_class }}">{{ private_chat_status }}</p>
                <p class="description">{{ private_chat_description }}</p>
            </div>
        </div>
    </div>
</body>
</html>
"""

WEBUI_STYLE = """
:root {
    color-scheme: dark;
    --bg: #050816;
    --panel: rgba(21, 28, 61, 0.82);
    --panel-border: rgba(93, 124, 255, 0.35);
    --primary: #4d7cff;
    --primary-light: #6ea6ff;
    --accent: #44d1ff;
    --text: #e6ecff;
    --muted: #9aa8d4;
    --danger: #f87272;
    --success: #4ade80;
    --border: rgba(148, 163, 184, 0.25);
    --surface-hover: rgba(148, 163, 184, 0.08);
    --input-bg: rgba(15, 23, 42, 0.6);
    --shadow: 0 26px 60px rgba(10, 18, 50, 0.45);
}
[data-theme="light"] {
    color-scheme: light;
    --bg: #f6f7ff;
    --panel: rgba(255, 255, 255, 0.90);
    --panel-border: rgba(93, 124, 255, 0.22);
    --primary: #395bff;
    --primary-light: #5f7cff;
    --accent: #2a7bff;
    --text: #1f245a;
    --muted: #5d6a9a;
    --danger: #f05f57;
    --success: #18a058;
    --border: rgba(92, 110, 170, 0.25);
    --surface-hover: rgba(92, 110, 170, 0.10);
    --input-bg: rgba(255, 255, 255, 0.92);
    --shadow: 0 18px 40px rgba(79, 105, 180, 0.28);
}
body {
    font-family: 'Inter', 'Segoe UI', 'PingFang SC', sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 24px;
    transition: background 0.35s ease, color 0.35s ease;
}
.login-body { padding: 0; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.container { max-width: 1180px; margin: 0 auto; }
header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
header h1 { font-size: 28px; margin: 0; }
.header-actions { display: flex; align-items: center; gap: 12px; }
.logout-link { padding: 8px 12px; border-radius: 12px; border: 1px solid var(--border); color: var(--text); background: var(--surface-hover); font-weight: 600; }
.logout-link:hover { background: rgba(93, 124, 255, 0.20); }
.card-grid { display: grid; gap: 18px; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); margin-bottom: 24px; }
.card { background: var(--panel); border: 1px solid var(--panel-border); border-radius: 22px; padding: 22px 20px 26px; box-shadow: var(--shadow); transition: transform 0.2s ease, box-shadow 0.2s ease; }
.card:hover { transform: translateY(-2px); box-shadow: 0 30px 70px rgba(12, 20, 46, 0.5); }
.card h3 { margin: 0 0 14px; font-size: 19px; color: var(--accent); }
.card p { margin: 6px 0; color: var(--text); }
.muted { color: var(--muted); }
.danger-text { color: var(--danger); }
.actions { margin-top: 12px; display: flex; flex-wrap: wrap; gap: 10px; }
.inline-form { display: inline-block; }
.btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 9px 16px; border-radius: 12px; border: none; cursor: pointer; font-weight: 600; text-decoration: none; transition: transform 0.2s ease, box-shadow 0.2s, background 0.2s; background: linear-gradient(135deg, var(--primary), var(--primary-light)); color: #f5f7ff; box-shadow: 0 16px 38px rgba(77, 124, 255, 0.35); }
.btn:hover { transform: translateY(-2px); box-shadow: 0 20px 46px rgba(77, 124, 255, 0.4); }
.btn.secondary { background: transparent; border: 1px solid var(--panel-border); color: var(--text); box-shadow: none; }
.btn.secondary:hover { background: var(--surface-hover); }
.btn.danger { background: linear-gradient(135deg, #f87171, #f43f5e); color: #fff; box-shadow: 0 16px 32px rgba(248, 113, 113, 0.35); }
input[type="text"], input[type="number"] {
    padding: 8px 10px;
    border-radius: 10px;
    border: 1px solid var(--border);
    background: var(--input-bg);
    color: var(--text);
    margin-right: 6px;
    outline: none;
    transition: border 0.2s ease, background 0.2s ease;
}
input[type="text"]:focus, input[type="number"]:focus {
    border-color: var(--accent);
    background: rgba(93, 124, 255, 0.15);
}
table { width: 100%; border-collapse: collapse; font-size: 14px; border-radius: 18px; overflow: hidden; }
table th, table td { border-bottom: 1px solid var(--border); padding: 10px 8px; text-align: left; color: var(--text); }
table th { color: var(--muted); font-size: 13px; font-weight: 600; letter-spacing: 0.03em; }
table tr:hover { background: var(--surface-hover); }
.notice { padding: 12px 16px; border-radius: 14px; margin-bottom: 20px; border: 1px solid transparent; font-size: 14px; }
.notice.success { background: rgba(74, 222, 128, 0.12); color: var(--success); border-color: rgba(74, 222, 128, 0.35); }
.notice.error { background: rgba(248, 113, 113, 0.12); color: var(--danger); border-color: rgba(248, 113, 113, 0.35); }
.small { color: var(--muted); font-size: 12px; }
section { margin-bottom: 28px; }
.theme-toggle {
    position: relative;
    width: 42px;
    height: 42px;
    border-radius: 50%;
    border: 1px solid var(--border);
    background: var(--panel);
    color: var(--text);
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    transition: background 0.2s ease, transform 0.2s ease;
}
.theme-toggle:hover { transform: translateY(-2px); background: var(--surface-hover); }
.theme-toggle .sun { display: none; }
[data-theme="light"] .theme-toggle .sun { display: inline; }
[data-theme="light"] .theme-toggle .moon { display: none; }
.theme-toggle .moon { display: inline; }
.login-container { display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 24px; }
.login-panel { width: clamp(320px, 90vw, 380px); background: var(--panel); border: 1px solid var(--panel-border); border-radius: 22px; padding: 26px 26px 30px; box-shadow: var(--shadow); }
.login-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.login-header h1 { margin: 0; font-size: 22px; }
.login-panel form { margin-top: 20px; display: flex; flex-direction: column; gap: 12px; }
.login-panel label { font-weight: 600; color: var(--text); }
.login-panel input[type="password"] { width: 100%; }
.login-panel button { margin-top: 8px; width: 100%; }
.login-footnote { margin-top: 18px; font-size: 13px; color: var(--muted); line-height: 1.7; }
.dual-column { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 18px; }
.section-with-table { overflow: hidden; border-radius: 20px; border: 1px solid var(--panel-border); background: var(--panel); box-shadow: var(--shadow); padding: 20px 22px 24px; }
.section-with-table h3 { margin-top: 0; margin-bottom: 14px; color: var(--accent); font-size: 18px; }
.analysis-table td:nth-child(3) { font-weight: 600; }
.analysis-table td:nth-child(7) { color: var(--muted); font-size: 12px; }
.analysis-table td:nth-child(8) { color: var(--muted); }
button:disabled, .btn:disabled { opacity: 0.6; cursor: not-allowed; box-shadow: none; }
@media (max-width: 720px) {
    body { padding: 20px; }
    header { flex-direction: column; align-items: flex-start; gap: 12px; }
    .header-actions { width: 100%; justify-content: space-between; }
    .card { padding: 18px; }
}
"""

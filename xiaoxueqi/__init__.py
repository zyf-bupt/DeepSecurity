"""Flask 应用工厂"""
import os
from flask import Flask, send_from_directory
from flask_cors import CORS
from config import Config


def create_app():
    app = Flask(__name__, static_folder='static')
    app.config.from_object(Config)

    # ---- CORS: 允许前端开发服务器跨域访问 ----
    CORS(app, resources={r"/*": {"origins": "*"}})

    # 注册蓝图
    from .views.main import bp as main_bp
    from .views.dashboard import bp as dashboard_bp
    from .views.log_view import bp as log_bp, api_bp as logontracer_api_bp
    from .views.behavior_view import bp as behavior_bp
    from .views.traffic_view import bp as traffic_bp
    from .views.attack_view import bp as attack_bp
    from .views.traceback_view import bp as traceback_bp
    from .views.detection_view import bp as detection_bp
    from .views.scenario_view import bp as scenario_bp
    from .views.attribution_view import bp as attribution_bp

    app.register_blueprint(main_bp)  # /
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
    app.register_blueprint(log_bp, url_prefix='/logs')
    app.register_blueprint(logontracer_api_bp, url_prefix='/api')
    app.register_blueprint(behavior_bp, url_prefix='/behavior')
    app.register_blueprint(traffic_bp, url_prefix='/traffic')
    app.register_blueprint(attack_bp, url_prefix='/attack')
    app.register_blueprint(traceback_bp, url_prefix='/traceback')
    app.register_blueprint(detection_bp, url_prefix='/detection')
    app.register_blueprint(scenario_bp, url_prefix='/scenario')
    app.register_blueprint(attribution_bp, url_prefix='/attribution')

    # ---- SPA 静态文件服务（生产模式） ----
    # 开发模式: Vite dev server :5173 → proxy API 请求到 Flask :5000
    # 生产模式: npm run build → xiaoxueqi/static/spa/ → 以下路由服务
    spa_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static', 'spa')

    @app.route('/spa/<path:filename>')
    def serve_spa_assets(filename: str):
        """服务 SPA 打包后的 JS/CSS/图片等静态资源"""
        if os.path.isdir(spa_dir):
            return send_from_directory(spa_dir, filename)
        from flask import abort
        abort(404)

    # 注意：开发模式下不需要生产模式路由。
    # 前端开发使用 Vite dev server (http://localhost:5173)，
    # 通过 vite.config.ts 中的 proxy 配置转发 API 到 Flask :5000。

    return app

"""溯归因分析视图"""
from flask import Blueprint, jsonify, render_template, request

from utils.attribution.attribution_engine import AttributionEngine
from utils.attribution.attacker_profiler import AttackerProfiler
from utils.attribution.report_generator import ReportGenerator
from utils.scenarios.scenario_manager import get_scenario_manager

bp = Blueprint("attribution", __name__)

attribution_engine = AttributionEngine()
attacker_profiler = AttackerProfiler()
report_generator = ReportGenerator()

# 缓存最近的分析结果
_cached_result: dict | None = None


@bp.route("/", methods=["GET"])
def index():
    return render_template("attribution_report.html")


@bp.route("/api/latest", methods=["GET"])
def api_latest_attribution():
    """获取最近的归因分析结果"""
    global _cached_result
    if _cached_result is None:
        return jsonify({"ok": False, "error": "暂无分析结果，请先运行分析"}), 404
    return jsonify({"ok": True, "data": _cached_result})


@bp.route("/api/attribute", methods=["POST"])
def api_attribute():
    """执行归因分析"""
    global _cached_result

    payload = request.get_json(silent=True) or {}
    data = payload.get("data")  # 可选: 从前端传入原始数据

    if data:
        verdict = data.get("verdict", {})
        chains = data.get("chains", [])
        evidence = data.get("evidence", [])
    else:
        # 如果没有传入数据，返回错误
        return jsonify({
            "ok": False,
            "error": "请提供分析数据或先执行完整分析管线 (POST /detection/api/analyze)"
        }), 400

    # 执行归因
    attribution_result = attribution_engine.attribute(
        verdict=verdict,
        chains=chains,
        evidence=evidence
    )

    # 构建画像
    profile = attacker_profiler.build_profile(
        attribution_data=attribution_result,
        behavioral=attribution_result.get("attribution", {}).get("result", {}).get(
            "behavioral_profile", {}),
        iocs=verdict.get("iocs", {}),
        ttps=attribution_result.get("ttps_extracted", [])
    )

    # 缓存
    _cached_result = {
        "attribution": attribution_result,
        "profile": profile,
        "timestamp": __import__("datetime").datetime.now().isoformat()
    }

    return jsonify({"ok": True, "data": _cached_result})


@bp.route("/api/report", methods=["GET"])
def api_report():
    """生成归因报告"""
    global _cached_result
    if _cached_result is None:
        return jsonify({"ok": False, "error": "暂无分析结果"}), 404

    report = report_generator.generate_comprehensive_report(
        verdict=_cached_result.get("attribution", {}).get("verdict", {}),
        attribution=_cached_result.get("attribution", {}),
        profile=_cached_result.get("profile", {}),
        chains=_cached_result.get("attribution", {}).get("chains", []),
        detection_stats={}
    )
    return jsonify({"ok": True, "data": report})


@bp.route("/api/apt/groups", methods=["GET"])
def api_apt_groups():
    """获取已知APT组织列表"""
    import json
    import os
    base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    path = os.path.join(base, "knowledge_base", "apt_groups.json")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return jsonify({"ok": True, "data": data})


@bp.route("/api/attck/techniques", methods=["GET"])
def api_attck_techniques():
    """获取ATT&CK技术列表"""
    import json
    import os
    base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    path = os.path.join(base, "knowledge_base", "attck_techniques.json")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return jsonify({"ok": True, "data": data})

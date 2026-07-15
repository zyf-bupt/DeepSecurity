"""检测仪表盘视图"""
from flask import Blueprint, jsonify, render_template, request

from utils.scenarios.scenario_manager import get_scenario_manager
from utils.detection.llm_detector import LLMDetector
from utils.detection.rag_knowledge_base import get_rag_kb
from utils.capture.agent_framework import get_capture_framework
from utils.attribution.attribution_engine import AttributionEngine
from utils.attribution.attacker_profiler import AttackerProfiler
from utils.attribution.report_generator import ReportGenerator

bp = Blueprint("detection", __name__)

# 初始化引擎
llm_detector = LLMDetector(use_llm=True)
attribution_engine = AttributionEngine()
attacker_profiler = AttackerProfiler()
report_generator = ReportGenerator()
rag_kb = get_rag_kb()


@bp.route("/", methods=["GET"])
def index():
    return render_template("detection.html")


@bp.route("/api/stats", methods=["GET"])
def api_stats():
    """获取检测统计"""
    mgr = get_scenario_manager()
    stats = mgr.get_detection_stats()
    detector_stats = llm_detector.get_stats()
    stats["detector"] = detector_stats
    return jsonify({"ok": True, "data": stats})


@bp.route("/api/alerts", methods=["GET"])
def api_alerts():
    """获取告警列表"""
    limit = request.args.get("limit", 50, type=int)
    severity = request.args.get("severity")
    scenario = request.args.get("scenario")

    mgr = get_scenario_manager()
    alerts = mgr.get_alerts(limit=limit, severity=severity, scenario_type=scenario)
    return jsonify({"ok": True, "data": alerts, "count": len(alerts)})


@bp.route("/api/alerts/live", methods=["GET"])
def api_alerts_live():
    """获取最新告警(用于实时轮询)"""
    mgr = get_scenario_manager()
    all_alerts = mgr.get_alerts(limit=10)
    # SSE 格式的数据
    return jsonify({
        "ok": True,
        "data": all_alerts,
        "timestamp": __import__("datetime").datetime.now().isoformat()
    })


@bp.route("/api/events/live", methods=["GET"])
def api_events_live():
    """获取最新事件"""
    mgr = get_scenario_manager()
    events = mgr.get_events(limit=50)
    return jsonify({"ok": True, "data": events, "count": len(events)})


@bp.route("/api/analyze", methods=["POST"])
def api_analyze():
    """一键执行完整分析管线: 检测→捕获→溯源"""
    mgr = get_scenario_manager()
    events = mgr.get_events(limit=500)

    if not events:
        return jsonify({"ok": False, "error": "无事件数据，请先启动场景"}), 400

    # 1. 检测阶段
    alerts = llm_detector.batch_detect(events)
    for alert in alerts:
        mgr.add_alert(alert)

    # 2. 捕获阶段
    capture_fw = get_capture_framework()
    capture_result = capture_fw.run(events, alerts)

    # 3. 溯源阶段
    attribution_result = attribution_engine.attribute(
        verdict=capture_result["verdict"],
        chains=capture_result["chains"],
        evidence=capture_result["evidence"]
    )

    ttps = attribution_result.get("ttps_extracted", []) or []
    knowledge_refs = rag_kb.collect_supporting_references(
        technique_ids=[t.get("technique_id", "") for t in ttps],
        technique_names=[t.get("technique_name", "") for t in ttps],
        apt_name=attribution_result.get("attribution", {}).get("result", {}).get("best_match", ""),
        top_k=4,
    )

    # 4. 攻击者画像
    profile = attacker_profiler.build_profile(
        attribution_data=attribution_result,
        behavioral=attribution_result.get("attribution", {}).get("result", {}).get("behavioral_profile", {}),
        iocs=capture_result["verdict"].get("iocs", {}),
        ttps=ttps
    )

    # 5. 生成报告
    report = report_generator.generate_comprehensive_report(
        verdict=capture_result["verdict"],
        attribution=attribution_result,
        profile=profile,
        chains=capture_result["chains"],
        detection_stats=mgr.get_detection_stats(),
        knowledge_refs=knowledge_refs,
    )

    # 6. 导出可视化数据
    vis_data = report_generator.export_visualization_data(
        chains=capture_result["chains"],
        attribution=attribution_result,
        profile=profile
    )

    return jsonify({
        "ok": True,
        "data": {
            "detection": {
                "alerts_count": len(alerts),
                "stats": llm_detector.get_stats()
            },
            "capture": {
                "verdict": capture_result["verdict"],
                "chains_count": len(capture_result["chains"]),
                "evidence_count": len(capture_result["evidence"])
            },
            "attribution": attribution_result,
            "profile": profile,
            "report": report,
            "visualization": vis_data,
            "knowledge_refs": knowledge_refs,
        }
    })


@bp.route("/api/report", methods=["GET"])
def api_report():
    """获取最近一次分析报告"""
    return jsonify({"ok": True, "message": "使用 /api/analyze 生成报告"})


@bp.route("/api/rag/search", methods=["GET"])
def api_rag_search():
    """RAG知识库搜索"""
    query = request.args.get("q", "")
    if not query:
        return jsonify({"ok": False, "error": "请提供搜索词"}), 400

    results = rag_kb.search(query, top_k=5)
    return jsonify({
        "ok": True,
        "data": results,
        "meta": {
            "backend": rag_kb.get_stats().get("backend", "tfidf"),
            "query": query,
            "count": len(results),
        }
    })


@bp.route("/api/knowledge", methods=["GET"])
def api_knowledge():
    """获取知识库概览"""
    return jsonify({"ok": True, "data": rag_kb.get_stats()})

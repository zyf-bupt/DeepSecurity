"""场景管理视图"""
from flask import Blueprint, jsonify, render_template, request

from utils.scenarios.scenario_manager import get_scenario_manager
from utils.network_env.network_env import get_network_env

bp = Blueprint("scenario", __name__)


@bp.route("/", methods=["GET"])
def index():
    return render_template("scenario.html")


@bp.route("/api/scenarios", methods=["GET"])
def api_scenarios():
    """获取所有场景"""
    mgr = get_scenario_manager()
    return jsonify({"ok": True, "data": mgr.get_scenarios()})


@bp.route("/api/scenarios/<scenario_id>/start", methods=["POST"])
def api_start_scenario(scenario_id: str):
    """启动场景"""
    mgr = get_scenario_manager()
    result = mgr.start_scenario(scenario_id)
    return jsonify(result)


@bp.route("/api/scenarios/<scenario_id>/stop", methods=["POST"])
def api_stop_scenario(scenario_id: str):
    """停止场景"""
    mgr = get_scenario_manager()
    result = mgr.stop_scenario(scenario_id)
    return jsonify(result)


@bp.route("/api/scenarios/stop_all", methods=["POST"])
def api_stop_all():
    """停止所有场景"""
    mgr = get_scenario_manager()
    result = mgr.stop_all()
    return jsonify(result)


@bp.route("/api/scenarios/<scenario_id>/status", methods=["GET"])
def api_scenario_status(scenario_id: str):
    """获取场景状态"""
    mgr = get_scenario_manager()
    result = mgr.get_scenario_status(scenario_id)
    return jsonify(result)


@bp.route("/api/status", methods=["GET"])
def api_all_status():
    """获取所有场景和系统的状态"""
    mgr = get_scenario_manager()
    net = get_network_env()
    return jsonify({
        "ok": True,
        "scenarios": mgr.get_all_status(),
        "network": net.get_security_posture()
    })


@bp.route("/api/events", methods=["GET"])
def api_events():
    """获取生成的事件"""
    limit = request.args.get("limit", 100, type=int)
    scenario_type = request.args.get("type")

    mgr = get_scenario_manager()
    events = mgr.get_events(limit=limit, scenario_type=scenario_type)
    return jsonify({"ok": True, "data": events, "count": len(events)})


@bp.route("/api/clear", methods=["POST"])
def api_clear():
    """清除事件和告警"""
    mgr = get_scenario_manager()
    mgr.clear_events()
    net = get_network_env()
    net.restore_all()
    return jsonify({"ok": True, "message": "已清除所有事件和告警，网络已恢复"})


@bp.route("/network", methods=["GET"])
def network_topology():
    """网络拓扑页面"""
    return render_template("network_topology.html")


@bp.route("/api/network", methods=["GET"])
def api_network():
    """获取网络拓扑数据"""
    net = get_network_env()
    return jsonify({
        "ok": True,
        "data": net.get_topology()
    })


@bp.route("/api/network/node/<node_id>", methods=["GET"])
def api_network_node(node_id: str):
    """获取单个节点信息"""
    net = get_network_env()
    node = net.get_node(node_id)
    if not node:
        return jsonify({"ok": False, "error": "节点不存在"}), 404
    return jsonify({"ok": True, "data": node.to_dict()})

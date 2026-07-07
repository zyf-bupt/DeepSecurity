"""
攻击场景基类
定义攻击生命周期的通用方法和接口
"""
import time
import uuid
import random
import threading
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any


class AttackScenario(ABC):
    """攻击场景基类"""

    def __init__(self, name: str, description: str, scenario_type: str):
        self.name = name
        self.description = description
        self.scenario_type = scenario_type
        self._running = False
        self._thread: threading.Thread | None = None
        self._stop_flag = False
        self._progress = 0
        self._current_stage = ""
        self._generated_events: list[dict] = []
        self._event_callbacks: list[callable] = []

    @abstractmethod
    def generate_attack_sequence(self) -> list[dict]:
        """生成攻击事件序列 - 子类实现"""
        pass

    def start(self, delay_between_stages: float = 2.0):
        """启动场景模拟"""
        if self._running:
            return {"ok": False, "error": "场景已在运行中"}

        self._running = True
        self._stop_flag = False
        self._progress = 0
        self._generated_events = []
        self._thread = threading.Thread(
            target=self._run_sequence,
            args=(delay_between_stages,),
            daemon=True
        )
        self._thread.start()
        return {"ok": True, "message": f"场景 '{self.name}' 已启动"}

    def stop(self):
        """停止场景"""
        self._stop_flag = True
        self._running = False
        self._current_stage = "已停止"
        return {"ok": True, "message": "场景已停止"}

    def _run_sequence(self, delay: float):
        """在后台线程中运行攻击序列"""
        try:
            stages = self.generate_attack_sequence()
            total_stages = len([s for s in stages if isinstance(s, dict) and s.get("type") == "stage"])

            completed = 0
            for item in stages:
                if self._stop_flag:
                    break

                if isinstance(item, dict) and item.get("type") == "stage":
                    self._current_stage = item.get("name", "Unknown Stage")
                    self._progress = int((completed / max(total_stages, 1)) * 100)

                    events = item.get("events", [])
                    for evt in events:
                        if self._stop_flag:
                            break
                        evt["scenario"] = self.name
                        evt["scenario_type"] = self.scenario_type
                        self._generated_events.append(evt)
                        self._notify_callbacks(evt)
                        time.sleep(random.uniform(0.1, 0.5))

                    completed += 1
                    time.sleep(delay)

            self._progress = 100
            self._current_stage = "攻击链完成"
        except Exception as e:
            self._current_stage = f"错误: {str(e)}"
        finally:
            self._running = False

    def on_event(self, callback: callable):
        """注册事件回调"""
        self._event_callbacks.append(callback)

    def _notify_callbacks(self, event: dict):
        for cb in self._event_callbacks:
            try:
                cb(event)
            except Exception:
                pass

    def get_status(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "type": self.scenario_type,
            "running": self._running,
            "progress": self._progress,
            "current_stage": self._current_stage,
            "events_generated": len(self._generated_events)
        }

    def get_events(self) -> list[dict]:
        return self._generated_events.copy()

    @staticmethod
    def _make_timestamp(offset_seconds: float = 0) -> str:
        return (datetime.now().isoformat() if offset_seconds == 0
                else datetime.now().isoformat())

    @staticmethod
    def _make_event(data_source: str, host_ip: str, event_type: str,
                    entities: dict | None = None, features: dict | None = None,
                    extra: dict | None = None) -> dict:
        evt = {
            "timestamp": datetime.now().isoformat(),
            "data_source": data_source,
            "host_ip": host_ip,
            "event_type": event_type,
            "entities": entities or {},
            "features": features or {}
        }
        if extra:
            evt.update(extra)
        return evt

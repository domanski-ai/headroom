import json
import os

import pytest

from headroom import route, supervisor


@pytest.fixture
def lane(tmp_path, monkeypatch):
    monkeypatch.setenv("HEADROOM_DIR", str(tmp_path / "headroom"))
    monkeypatch.delenv("HEADROOM_LANE_CONFIG_DIR", raising=False)
    monkeypatch.setattr(route, "dispatch_dir", lambda account: account["home"])
    home = tmp_path / "seat"
    home.mkdir()
    return {"name": "lane-a", "provider": "claude", "home": str(home)}


def write_settings(directory, document):
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, "settings.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle)
    return path


def generated_document(runner, account, generation=1):
    path = runner._settings_file(generation, account)
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def test_model_settings_wins_over_top_level(lane, monkeypatch):
    path = write_settings(lane["home"], {
        "effortLevel": "low",
        "modelSettings": {"claude-opus-5": {"effortLevel": "xhigh"}},
    })
    notices = []
    monkeypatch.setattr(supervisor, "_operator_notice", notices.append)

    document = generated_document(supervisor.Supervisor("opus", [], lane), lane)

    assert document["effortLevel"] == "xhigh"
    assert notices == [
        f"effort xhigh from modelSettings.claude-opus-5 in {path}"]


def test_top_level_is_used_when_model_pick_is_absent(lane, monkeypatch):
    path = write_settings(lane["home"], {
        "effortLevel": "high",
        "modelSettings": {"claude-sonnet-5": {"effortLevel": "low"}},
    })
    notices = []
    monkeypatch.setattr(supervisor, "_operator_notice", notices.append)

    document = generated_document(supervisor.Supervisor("opus", [], lane), lane)

    assert document["effortLevel"] == "high"
    assert notices == [f"effort high from effortLevel in {path}"]


@pytest.mark.parametrize(("model", "model_id"), [
    ("opus[1m]", "claude-opus-5"),
    ("fable", "claude-fable-5"),
    ("sonnet", "claude-sonnet-5"),
    ("haiku", "claude-haiku-4-5-20251001"),
    ("claude-custom-5", "claude-custom-5"),
])
def test_launch_model_aliases_and_full_ids(lane, model, model_id):
    write_settings(lane["home"], {
        "modelSettings": {model_id: {"effortLevel": "high"}},
    })

    document = generated_document(supervisor.Supervisor(model, [], lane), lane)

    assert document["effortLevel"] == "high"


def test_nothing_is_carried_when_neither_key_exists(lane, monkeypatch):
    path = write_settings(lane["home"], {"modelSettings": {}})
    notices = []
    monkeypatch.setattr(supervisor, "_operator_notice", notices.append)

    document = generated_document(supervisor.Supervisor("opus", [], lane), lane)

    assert "effortLevel" not in document
    assert notices == [f"no effort pick in {path}"]


def test_explicit_settings_effort_is_kept(lane, tmp_path, monkeypatch):
    path = write_settings(lane["home"], {"effortLevel": "low"})
    explicit = tmp_path / "explicit.json"
    explicit.write_text(json.dumps({"effortLevel": "xhigh"}), encoding="utf-8")
    notices = []
    monkeypatch.setattr(supervisor, "_operator_notice", notices.append)
    runner = supervisor.Supervisor(
        "opus", ["--settings", str(explicit)], lane)

    document = generated_document(runner, lane)

    assert document["effortLevel"] == "xhigh"
    assert notices == [f"effort low from effortLevel in {path}"]


@pytest.mark.parametrize("contents", [None, "{not json", "[]"])
def test_missing_corrupt_or_non_object_settings_do_not_raise(
        lane, contents, monkeypatch):
    path = os.path.join(lane["home"], "settings.json")
    if contents is not None:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(contents)
    notices = []
    monkeypatch.setattr(supervisor, "_operator_notice", notices.append)

    document = generated_document(supervisor.Supervisor("opus", [], lane), lane)

    assert "effortLevel" not in document
    assert notices == [f"no effort pick in {path}"]


def test_unreadable_settings_do_not_raise(lane, monkeypatch):
    path = os.path.join(lane["home"], "settings.json")
    notices = []
    monkeypatch.setattr(supervisor, "_operator_notice", notices.append)
    real_open = open

    def refuse_lane_settings(candidate, *args, **kwargs):
        if os.fspath(candidate) == path:
            raise PermissionError("unreadable")
        return real_open(candidate, *args, **kwargs)

    monkeypatch.setattr("builtins.open", refuse_lane_settings)
    document = generated_document(supervisor.Supervisor("opus", [], lane), lane)

    assert "effortLevel" not in document
    assert notices == [f"no effort pick in {path}"]


def test_each_settings_generation_rereads_the_lane_pick(lane):
    write_settings(lane["home"], {"effortLevel": "low"})
    runner = supervisor.Supervisor("opus", [], lane)

    first = generated_document(runner, lane, generation=1)
    write_settings(lane["home"], {"effortLevel": "xhigh"})
    resumed = generated_document(runner, lane, generation=2)

    assert first["effortLevel"] == "low"
    assert resumed["effortLevel"] == "xhigh"


def test_lane_config_dir_is_preferred_and_seat_home_is_the_fallback(
        lane, tmp_path, monkeypatch):
    lane_dir = tmp_path / "lane-config"
    write_settings(lane["home"], {"effortLevel": "high"})
    write_settings(lane_dir, {"effortLevel": "low"})

    seat_document = generated_document(
        supervisor.Supervisor("opus", [], lane), lane)
    monkeypatch.setenv("HEADROOM_LANE_CONFIG_DIR", str(lane_dir))
    lane_document = generated_document(
        supervisor.Supervisor("opus", [], lane), lane, generation=2)

    assert seat_document["effortLevel"] == "high"
    assert lane_document["effortLevel"] == "low"

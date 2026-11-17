import os
import shutil
import signal
import time

import pytest
from dasbus.error import DBusError
from dasbus.typing import Bool, List, Str, get_native, get_variant

from conftest import have_streaming, needs_polkit

pytestmark = needs_polkit


@pytest.fixture
def bundle(tmp_path):
    shutil.copyfile("good-verity-bundle.raucb", tmp_path / "good-verity-bundle.raucb")
    return str(tmp_path / "good-verity-bundle.raucb")


def slot_written(path):
    return path.exists() and path.stat().st_size > 0


def wait_idle(proxy):
    """Wait for an install the service accepted to end, and return its error."""
    timeout = time.monotonic() + 30.0
    while proxy.Operation != "idle":
        assert time.monotonic() < timeout, "install did not finish"
        time.sleep(0.1)
    return proxy.LastError


def test_install_refused(rauc_dbus_service_with_system, polkit_allow, bundle, tmp_path):
    polkit_allow()

    with pytest.raises(DBusError, match="not authorized"):
        rauc_dbus_service_with_system.InstallBundle(bundle, {})

    assert not slot_written(tmp_path / "images/rootfs-1")


def test_install_allowed(rauc_dbus_service_with_system, polkit_allow, bundle, tmp_path):
    polkit_allow("de.pengutronix.rauc.install")

    rauc_dbus_service_with_system.InstallBundle(bundle, {})

    assert wait_idle(rauc_dbus_service_with_system) == ""
    assert slot_written(tmp_path / "images/rootfs-1")


@pytest.mark.parametrize("override", ["ignore-compatible", "ignore-version-limit", "tls-no-verify"])
def test_install_override_refused(rauc_dbus_service_with_system, polkit_allow, bundle, tmp_path, override):
    polkit_allow("de.pengutronix.rauc.install")

    with pytest.raises(DBusError, match="not authorized"):
        rauc_dbus_service_with_system.InstallBundle(bundle, {override: get_variant(Bool, True)})

    assert not slot_written(tmp_path / "images/rootfs-1")


@pytest.mark.parametrize(
    "arg",
    [
        ("tls-cert", get_variant(Str, "/etc/shadow")),
        ("tls-key", get_variant(Str, "pkcs11:token=any")),
        ("tls-ca", get_variant(Str, "/tmp/ca.pem")),
        ("http-headers", get_variant(List[Str], ["X-Any: value"])),
    ],
)
def test_install_tls_args_need_override(rauc_dbus_service_with_system, polkit_allow, bundle, tmp_path, arg):
    polkit_allow("de.pengutronix.rauc.install")

    with pytest.raises(DBusError, match="not authorized"):
        rauc_dbus_service_with_system.InstallBundle(bundle, {arg[0]: arg[1]})

    assert not slot_written(tmp_path / "images/rootfs-1")


def test_install_override_allowed(rauc_dbus_service_with_system, polkit_allow, bundle, tmp_path):
    polkit_allow("de.pengutronix.rauc.install-override")

    rauc_dbus_service_with_system.InstallBundle(bundle, {"ignore-compatible": get_variant(Bool, True)})

    assert wait_idle(rauc_dbus_service_with_system) == ""
    assert slot_written(tmp_path / "images/rootfs-1")


def test_mark_refused(rauc_dbus_service_with_system, polkit_allow):
    polkit_allow("de.pengutronix.rauc.install")

    with pytest.raises(DBusError, match="not authorized"):
        rauc_dbus_service_with_system.Mark("good", "booted")


def test_mark_allowed(rauc_dbus_service_with_system, polkit_allow):
    polkit_allow("de.pengutronix.rauc.mark")

    slot, _ = rauc_dbus_service_with_system.Mark("good", "booted")

    assert slot == "rootfs.0"


def test_inspect_refused(rauc_dbus_service_with_system, polkit_allow, bundle):
    polkit_allow("de.pengutronix.rauc.install")

    with pytest.raises(DBusError, match="not authorized"):
        rauc_dbus_service_with_system.InspectBundle(bundle, {})
    with pytest.raises(DBusError, match="not authorized"):
        rauc_dbus_service_with_system.Info(bundle)


def test_inspect_allowed(rauc_dbus_service_with_system, polkit_allow, bundle):
    polkit_allow("de.pengutronix.rauc.inspect")

    rauc_dbus_service_with_system.InspectBundle(bundle, {})
    compatible, version = rauc_dbus_service_with_system.Info(bundle)

    assert (compatible, version) == ("Test Config", "2011.03-2")


@pytest.mark.parametrize(
    "arg",
    [
        ("tls-cert", get_variant(Str, "/etc/shadow")),
        ("tls-key", get_variant(Str, "pkcs11:token=any")),
        ("tls-ca", get_variant(Str, "/tmp/ca.pem")),
        ("tls-no-verify", get_variant(Bool, True)),
        ("http-headers", get_variant(List[Str], ["X-Any: value"])),
    ],
)
def test_inspect_tls_args_need_override(rauc_dbus_service_with_system, polkit_allow, bundle, arg):
    polkit_allow("de.pengutronix.rauc.inspect")

    with pytest.raises(DBusError, match="not authorized"):
        rauc_dbus_service_with_system.InspectBundle(bundle, {arg[0]: arg[1]})


def test_inspect_override_allowed(rauc_dbus_service_with_system, polkit_allow, bundle):
    polkit_allow("de.pengutronix.rauc.inspect-override")

    manifest = get_native(
        rauc_dbus_service_with_system.InspectBundle(bundle, {"tls-no-verify": get_variant(Bool, True)})
    )

    assert manifest["update"]["compatible"] == "Test Config"


def test_read_only_methods_not_checked(rauc_dbus_service_with_system, polkit_allow):
    polkit_allow()

    rauc_dbus_service_with_system.GetSlotStatus()
    rauc_dbus_service_with_system.GetPrimary()


@have_streaming
def test_poll(create_system_files, system, http_server, polkit_allow):
    http_server.setup(file_path="good-verity-bundle.raucb")
    system.prepare_minimal_config()
    system.config["handlers"] = {"system-info": "bin/systeminfo.sh"}
    system.config["polling"] = {"url": http_server.url, "interval-sec": "60"}
    system.write_config()

    with system.running_service("A"):
        polkit_allow("de.pengutronix.rauc.install")
        with pytest.raises(DBusError, match="not authorized"):
            system.proxy.Poll()

        polkit_allow("de.pengutronix.rauc.poll")
        system.proxy.Poll()


def test_transaction_id_needs_override(rauc_dbus_service_with_system, polkit_allow, bundle, tmp_path):
    polkit_allow("de.pengutronix.rauc.install")

    with pytest.raises(DBusError, match="not authorized"):
        rauc_dbus_service_with_system.InstallBundle(bundle, {"transaction-id": get_variant(Str, "x\r\nX-Injected: 1")})

    assert not slot_written(tmp_path / "images/rootfs-1")


def test_details_hide_tls_values(rauc_dbus_service_with_system, polkit_allow, bundle):
    polkit_allow()
    polkit_allow.calls()

    with pytest.raises(DBusError, match="not authorized"):
        rauc_dbus_service_with_system.InstallBundle(
            bundle,
            {
                "tls-key": get_variant(Str, "pkcs11:token=t;object=k?pin-value=SECRET"),
                "tls-cert": get_variant(Str, "pkcs11:token=t;object=c?pin-value=SECRET"),
            },
        )
    with pytest.raises(DBusError, match="not authorized"):
        rauc_dbus_service_with_system.Mark("good", "booted")

    (install_action, install), (mark_action, mark) = polkit_allow.calls()
    assert install_action == "de.pengutronix.rauc.install-override"
    assert install["source"] == bundle
    assert install["tls-key"] == "true"
    assert install["tls-cert"] == "true"
    assert install["tls-ca"] == "false"
    assert not any("SECRET" in v for v in install.values())
    assert mark_action == "de.pengutronix.rauc.mark"
    assert mark == {"state": "good", "slot": "booted"}


def test_refused_when_polkit_does_not_answer(rauc_dbus_service_with_system, polkit_allow):
    polkit_allow("de.pengutronix.rauc.mark")
    os.kill(polkit_allow.pid, signal.SIGSTOP)
    try:
        start = time.monotonic()
        with pytest.raises(DBusError, match="polkit did not answer in time"):
            rauc_dbus_service_with_system.Mark("good", "booted")
        assert 15 < time.monotonic() - start < 25
    finally:
        os.kill(polkit_allow.pid, signal.SIGCONT)

    # and works again once polkit answers
    rauc_dbus_service_with_system.Mark("good", "booted")


def test_mark_refused_when_install_starts_during_check(rauc_dbus_service_with_system, polkit_allow, bundle):
    """An install authorized while a Mark() check is pending makes the Mark() busy."""
    import threading

    from dasbus.connection import SessionMessageBus

    polkit_allow("de.pengutronix.rauc.install", "de.pengutronix.rauc.mark")
    results = {}

    def call(name, *args):
        proxy = SessionMessageBus().get_proxy("de.pengutronix.rauc", "/")
        try:
            results[name] = getattr(proxy, name)(*args)
        except DBusError as e:
            results[name] = e

    os.kill(polkit_allow.pid, signal.SIGSTOP)
    try:
        install = threading.Thread(target=call, args=("InstallBundle", bundle, {}))
        install.start()
        time.sleep(1)
        mark = threading.Thread(target=call, args=("Mark", "good", "booted"))
        mark.start()
        time.sleep(1)
    finally:
        os.kill(polkit_allow.pid, signal.SIGCONT)
    install.join(timeout=30)
    mark.join(timeout=30)

    assert not isinstance(results["InstallBundle"], DBusError)
    assert isinstance(results["Mark"], DBusError)
    assert "already processing a different method" in str(results["Mark"])
    assert wait_idle(rauc_dbus_service_with_system) == ""

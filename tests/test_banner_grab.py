"""Tests for service-specific banner parsing.

These tests exercise `parse_service` directly with realistic banner
strings; the network/probe path is covered indirectly by the demo and
doesn't need a unit test here.
"""
from __future__ import annotations

from vuln_platform.scanner.banner_grab import parse_service


def test_apache_http_banner() -> None:
    banner = (
        "HTTP/1.0 200 OK\r\n"
        "Server: Apache/2.4.49 (Unix)\r\n"
        "Content-Type: text/plain\r\n"
    )
    svc = parse_service(80, banner)
    assert svc.name == "apache"
    assert svc.version == "2.4.49"


def test_nginx_http_banner() -> None:
    banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n"
    svc = parse_service(80, banner)
    assert svc.name == "nginx"
    assert svc.version == "1.25.3"


def test_openssh_banner() -> None:
    banner = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"
    svc = parse_service(22, banner)
    assert svc.name == "openssh"
    assert svc.version == "9.6p1"


def test_dropbear_ssh_banner() -> None:
    banner = "SSH-2.0-dropbear_2022.83\r\n"
    svc = parse_service(22, banner)
    assert svc.name == "dropbear"
    assert svc.version == "2022.83"


def test_postfix_smtp_with_ehlo_response() -> None:
    banner = (
        "220 mail.example.com ESMTP Postfix (Ubuntu)\r\n"
        "250-mail.example.com\r\n"
        "250-PIPELINING\r\n"
        "250 SIZE 10240000\r\n"
    )
    svc = parse_service(25, banner)
    assert svc.name == "postfix"


def test_exim_smtp() -> None:
    banner = "220 mail.example.com ESMTP Exim 4.95 Tue, 23 Apr 2024 12:00:00 +0000\r\n"
    svc = parse_service(25, banner)
    assert svc.name == "exim"
    assert svc.version == "4.95"


def test_redis_info_response() -> None:
    banner = (
        "$1234\r\n"
        "# Server\r\n"
        "redis_version:7.0.5\r\n"
        "redis_git_sha1:00000000\r\n"
    )
    svc = parse_service(6379, banner)
    assert svc.name == "redis"
    assert svc.version == "7.0.5"


def test_vsftpd_banner() -> None:
    banner = "220 (vsFTPd 3.0.3)\r\n"
    svc = parse_service(21, banner)
    assert svc.name == "vsftpd"
    assert svc.version == "3.0.3"


def test_proftpd_banner() -> None:
    banner = "220 ProFTPD 1.3.7 Server (Debian) [::ffff:1.2.3.4]\r\n"
    svc = parse_service(21, banner)
    assert svc.name == "proftpd"
    assert svc.version == "1.3.7"


def test_dovecot_pop3_banner() -> None:
    banner = "+OK Dovecot (Ubuntu) ready.\r\n"
    svc = parse_service(110, banner)
    assert svc.name == "dovecot"


def test_dovecot_imap_banner() -> None:
    banner = "* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+] Dovecot (Ubuntu) ready.\r\n"
    svc = parse_service(143, banner)
    assert svc.name == "dovecot"


def test_unknown_port_falls_back_to_default() -> None:
    svc = parse_service(54321, "garbage")
    assert svc.name == "unknown-54321"


def test_empty_banner_returns_well_known_name() -> None:
    svc = parse_service(22, None)
    assert svc.name == "ssh"
    assert svc.version is None

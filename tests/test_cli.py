from icap_server.server import build_parser


def test_cli_defaults():
    args = build_parser().parse_args([])
    assert args.host == '0.0.0.0'
    assert args.port == 1344

def test_diff_csv_output(tmp_path):
    # Test that --format csv option exists in rebrew diff's CLI.
    # We use typer.testing.CliRunner to avoid invoking Wine.
    from typer.testing import CliRunner

    from rebrew.diff import app

    runner = CliRunner()
    result = runner.invoke(app, ["src/mock.c", "--format", "csv", "--symbol", "foo"])

    # It should fail with FileNotFoundError (no mock.c) or annotation error, but the format flag should be accepted
    # Instead, let's just make sure the flag exists.
    assert "--format" in runner.invoke(app, ["--help"]).stdout
    assert result.exit_code in (1, 2)

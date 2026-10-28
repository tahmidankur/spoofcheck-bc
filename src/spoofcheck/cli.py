import typer

from spoofcheck import __version__

app = typer.Typer(no_args_is_help=True, add_completion=False)


@app.command()
def version() -> None:
    typer.echo(__version__)

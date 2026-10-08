def test_engine_module_loads():
    import stackencrypt

    assert isinstance(stackencrypt.engine_version(), str)
    assert stackencrypt.engine_version() != ""

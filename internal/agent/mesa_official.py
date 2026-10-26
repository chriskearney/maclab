"""Optional official65 adapter is fail-closed until its reviewed source lands."""
def run_official(plan,manifest,output_dir,command_env,system_graphics_pins):
    raise RuntimeError('official GPU adapter not implemented/reviewed; no official execution')

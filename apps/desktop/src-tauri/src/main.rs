// Hide the console window on Windows release builds. A GUI app that flashes a
// terminal behind itself looks broken.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // The elevated helper. Windows re-launches this same executable with
    // `--allow-firewall` after the user approves the UAC prompt; it adds the
    // firewall rule and exits without ever creating a window.
    //
    // Checked before anything else so an elevated instance can never
    // accidentally start a second copy of the app, bind the port, and confuse
    // the running one.
    if std::env::args_os().any(|arg| arg == jetstream_discovery::firewall::INSTALL_ARG) {
        std::process::exit(jetstream_lib::install_firewall_rule());
    }

    // The other privileged job: moving an unidentified network off Public, which
    // Windows will not let the user do from Settings for that kind of network.
    if std::env::args_os().any(|arg| arg == jetstream_discovery::netprofile::SET_PRIVATE_ARG) {
        std::process::exit(jetstream_lib::set_network_private());
    }

    jetstream_lib::run()
}

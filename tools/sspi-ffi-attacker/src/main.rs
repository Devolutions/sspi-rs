mod attack;
mod types;
mod utils;

use std::{env, path::Path};

use attack::{attack_w, attac_auth_identity, init_w_table, init_a_table, attack_a};

fn main() {
    let args: Vec<String> = env::args().collect();

    let path_to_library = if let Some(path) = args.get(1) {
        path
    } else {
        panic!("DLL path is not provided");
    };

    if !Path::new(path_to_library).exists() {
        panic!("Provided path does not exist: {:?}", path_to_library);
    }

    unsafe {
        let sec_w_table = init_w_table(path_to_library);
        attack_w(sec_w_table);
        let _ = Box::from_raw(sec_w_table);

        let sec_a_table = init_a_table(path_to_library);
        attack_a(sec_a_table);
        let _ = Box::from_raw(sec_a_table);

        attac_auth_identity(path_to_library);
    }
}

use std::io;
use std::process::Command;
use anyhow::{Result, anyhow};
use cliclack::{input, intro, note, outro, password, select, spinner};
use crate::client::auth::*;
use crate::client::crypto::{decrypt_rsa_oaep, decrypt_xchacha20_poly1305};
use crate::client::file_manager::*;
use crate::client::session::*;
use crate::client::utils::contains_non_alphanumeric;
use crate::models::{UserMetadata};
use crate::server::api::*;

// Function to display a welcome message with ASCII art.
pub fn welcome() {
    println!(r"
     __          __  _                            _
     \ \        / / | |                          | |
      \ \  /\  / /__| | ___ ___  _ __ ___   ___  | |_ ___
       \ \/  \/ / _ \ |/ __/ _ \| '_ ` _ \ / _ \ | __/ _ \
        \  /\  /  __/ | (_| (_) | | | | | |  __/ | || (_) |
      ___\/  \/ \___|_|\___\___/|_| |_| |_|\___|  \__\___/
     |  __ \           | |   / ____| |               | |
     | |  | |_   _  ___| | _| |    | | ___  _   _  __| |
     | |  | | | | |/ __| |/ / |    | |/ _ \| | | |/ _` |
     | |__| | |_| | (__|   <| |____| | (_) | |_| | (_| |
     |_____/ \__,_|\___|_|\_\\_____|_|\___/ \__,_|\__,_|

                            ██████████
                          ██░░░░░░░░░░██
                        ██░░░░░░░░░░░░░░██
                        ██░░░░░░░░████░░██████████
            ██          ██░░░░░░░░████░░██▒▒▒▒▒▒██
          ██░░██        ██░░░░░░░░░░░░░░██▒▒▒▒▒▒██
          ██░░░░██      ██░░░░░░░░░░░░░░████████
        ██░░░░░░░░██      ██░░░░░░░░░░░░██
        ██░░░░░░░░████████████░░░░░░░░██
        ██░░░░░░░░██░░░░░░░░░░░░░░░░░░░░██
        ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██
        ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██
        ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██
        ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██
        ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██
        ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██
          ██░░░░░░░░░░░░░░░░░░░░░░░░░░██
            ██████░░░░░░░░░░░░░░░░████
                  ████████████████

    ");
}

// Function to manage the initial connection and authentication process.
pub fn connection_info() -> Result<()> {
    loop {
        clear_console();
        welcome();

        // Display options to register, login, or exit.
        let choice = select("Already have an account?")
            .item("1", "Register", "")
            .item("2", "Login", "")
            .item("3", "Exit", "")
            .interact()?;

        match choice {
            "1" => register()?,  // Call the register function.
            "2" => login()?,     // Call the login function.
            "3" => {
                outro("Goodbye!").unwrap();
                break;  // Exit the loop and the program.
            }
            _ => println!("Invalid choice. Please select a valid option."),
        }
    }

    Ok(())
}

// Function to clear the console screen.
fn clear_console() {
    Command::new("clear")
        .status()
        .unwrap();
}

// Function to pause and wait for user input to continue.
fn pause() {
    outro("Press any key to continue...").unwrap();
    io::stdin()
        .read_line(&mut String::new())
        .expect("Failed to read line");
}

// Function to handle user registration.
fn register() -> Result<()> {
    clear_console();
    intro("Register a new user")?;

    // Prompt for username and validate input.
    let username: String = input("Enter your username:")
        .validate(|input: &String| {
            if input.trim().is_empty() {
                Err("Username cannot be empty.")
            } else if contains_non_alphanumeric(input) {
                Err("Username can only contain alphanumeric characters.")
            } else {
                Ok(())
            }
        })
        .interact()?;

    // Prompt for password and validate input.
    let password_input: String = password("Enter your password:")
        .mask('*')
        .interact()?;

    // Clone the password for confirmation.
    let password_clone = password_input.clone();

    // Prompt for password confirmation and validate input.
    password("Confirm your password:")
        .mask('*')
        .validate(move |input: &String| {
            if *input != password_clone {
                Err("Passwords do not match.")
            } else {
                Ok(())
            }
        })
        .interact()?;

    // Create a spinner to show progress during registration.
    let mut spinner = spinner();
    spinner.start("Registering...");

    // Attempt to register the user.
    match register_compute(&username, &password_input) {
        Ok(_) => {
            spinner.stop("Registration successful.");
        },
        Err(err) => {
            spinner.stop(format!("Registration failed : {}", err.to_string().as_str()));
        }
    }

    // Pause to allow the user to read the result.
    pause();
    Ok(())
}

// Function to compute registration data and perform registration.
fn register_compute(username: &str, password: &str) -> Result<()> {
    // Compute cryptographic keys and user data for registration.
    let (master_password_hash, protected_symmetric_key, protected_private_key, public_key_bytes) =
        register_keys_create(&username.trim().to_ascii_lowercase(), password)?;

    // Create user metadata with computed data.
    let mut user_data = UserMetadata {
        username: username.to_string(),
        master_password_hash,
        protected_symmetric_key,
        protected_private_key,
        public_key_bytes,
        shares: vec![],
    };

    // Call the registration endpoint.
    register_endpoint(&mut user_data)
}

// Function to handle user login.
fn login() -> Result<()> {
    clear_console();
    intro("Login")?;

    // Prompt for username and password.
    let username: String = input("Enter your username:")
        .interact()?;
    let password: String = password("Enter your password:")
        .mask('*')
        .interact()?;

    // Create a spinner to show progress during login.
    let mut spinner = spinner();
    spinner.start("Logging in...");

    // Attempt to perform login.
    match login_compute(&username, &password) {
        Ok(_) => {
            spinner.stop("Login successful.");
            pause();
            file_manager_menu()?;  // Call the file_manager_menu function after successful login.
        }
        Err(err) => {
            spinner.stop(format!("Login failed : {}", err.to_string().as_str()));
            pause();
        }
    }

    Ok(())
}

// Function to compute login data and perform login.
fn login_compute(username: &str, password: &str) -> Result<String> {
    let username = username.trim().to_ascii_lowercase();
    let username = username.as_str();

    // Compute master password hash for login.
    let calculated_master_password_hash = login_mph_compute(username, password)?;

    // Call the login endpoint and handle the response.
    match login_endpoint(username, &calculated_master_password_hash) {
        Ok((message, mut user_data, directory_metadata)) => {
            let stretched_master_key = login_smk_compute(username, password)?;

            // Set up the user session and handle any errors.
            match login_set_session(username, &mut user_data, stretched_master_key, directory_metadata) {
                Ok(_) => Ok(message),
                Err(err) => Err(err),
            }
        }
        Err(err) => Err(err),
    }
}

// Function to display the file manager menu after successful login.
fn file_manager_menu() -> Result<()> {
    loop {
        clear_console();
        intro(format!("Welcome {}!", get_username().unwrap()))?;
        note("Current directory", get_clear_path().unwrap())?;

        // Display options for file and folder management.
        let choice = select("Select an option")
            .item("1", "List files and folders", "")
            .item("2", "Change directory", "")
            .item("3", "Create a new folder", "")
            .item("4", "Upload a file", "")
            .item("5", "Download a file", "")
            .item("6", "Delete a file", "")
            .item("7", "Share a folder", "")
            .item("8", "Unshare a folder", "")
            .item("9", "Change password", "")
            .item("10", "Logout", "")
            .interact()?;

        match choice {
            "1" => list_content(),            // Call the list_content function to list current directory contents.
            "2" => change_directory_menu()?,  // Call the change_directory_menu function to change the current directory.
            "3" => create_new_folder_menu()?, // Call the create_new_folder_menu function to create a new folder.
            "4" => upload_file_menu()?,       // Call the upload_file_menu function to upload a file.
            "5" => download_file_menu()?,     // Call the download_file_menu function to download a file.
            "6" => delete_file_menu()?,       // Call the delete_file_menu function to delete a file.
            "7" => share_folder_menu()?,      // Call the share_folder_menu function to share a folder.
            "8" => unshare_folder_menu()?,    // Call the unshare_folder_menu function to unshare a folder.
            "9" => {
                change_password_menu()?;      // Call the change_password_menu function to change the user's password.
                clear_session();
                break;
            }
            "10" => {
                clear_session();
                break;  // Exit the loop and log out the user.
            }
            _ => println!("Invalid choice. Please select a valid option."),
        }
    }
    Ok(())
}

// Function to list the contents (folders and files) of the current directory.
fn list_content() {
    clear_console();

    // Retrieve the current directory map.
    let dir_map = match get_current_directory_map() {
        Some(val) => val,
        None => {
            note("Error", "Unable to access current directory map.").unwrap();
            pause();
            return;
        }
    };

    intro("Current directory content").unwrap();

    if dir_map.folders.is_empty() && dir_map.files.is_empty() {
        println!("(empty)");
    } else {
        if !dir_map.folders.is_empty() {
            println!("\x1B[90m├── Folders:\x1B[0m");
            for (folder_name, _) in dir_map.folders.iter() {
                let shared = dir_map.sharing_state.get(folder_name).unwrap_or(&false);
                let display_name = if *shared { format!("{} (s)", folder_name) } else { folder_name.clone() };
                println!("\x1B[90m│   └── {}\x1B[0m", display_name);
            }
        }

        if !dir_map.files.is_empty() {
            println!("\x1B[90m├── Files:\x1B[0m");
            for (file_name, _) in dir_map.files.iter() {
                println!("\x1B[90m│   └── {}\x1B[0m", file_name);
            }
        }
    }

    pause();
}

// Function to handle changing the current directory.
fn change_directory_menu() -> Result<()> {
    clear_console();
    intro("Change directory")?;

    // Retrieve the current directory map.
    let dir_map = get_current_directory_map()
        .ok_or_else(|| anyhow!("Unable to access current directory map."))?;

    let mut items = Vec::new();
    items.push(("..".to_string(), ".. (up a directory)".to_string(), ""));
    for (folder_name, _) in dir_map.folders.iter() {
        let shared = dir_map.sharing_state.get(folder_name).unwrap_or(&false);
        let display_name = if *shared { format!("{} (s)", folder_name) } else { folder_name.clone() };
        items.push((folder_name.clone(), display_name, ""));
    }

    let selected_folder = select("Select a folder:")
        .items(&items)
        .interact()?;

    // Attempt to change the current directory and display the result.
    match change_directory(&selected_folder) {
        Ok(confirmation) => note("Directory changed", confirmation)?,
        Err(err) => note("Directory change failed", err.to_string())?,
    }

    pause();
    Ok(())
}

// Function to handle creating a new folder.
fn create_new_folder_menu() -> Result<()> {
    clear_console();
    intro("Create a new folder")?;

    // Prompt for the folder name and validate input.
    let folder_name: String = input("Enter the name of the folder to create:")
        .validate(|input: &String| {
            if contains_non_alphanumeric(input) {
                Err("Username can only contain alphanumeric characters.")
            } else {
                Ok(())
            }
        })
        .interact()?;

    // Attempt to create a new folder and display the result.
    match create_folder(&folder_name) {
        Ok(_) => note("Folder created", format!("Folder '{}' has been successfully created.", folder_name))?,
        Err(err) => note("Folder creation failed", err.to_string())?,
    }

    pause();
    Ok(())
}

// Function to handle uploading a file to the server.
fn upload_file_menu() -> Result<()> {
    clear_console();
    intro("Upload a file to the server")?;

    // Prompt for the file name.
    let file_name: String = input("Enter the name of the file to upload:")
        .interact()?;

    // Attempt to upload the file and display the result.
    match upload_file(&file_name) {
        Ok(_) => note("File uploaded", format!("File '{}' has been successfully uploaded.", file_name))?,
        Err(err) => note("File upload failed", err.to_string())?,
    }

    pause();
    Ok(())
}

// Function to handle downloading a file from the server.
fn download_file_menu() -> Result<()> {
    clear_console();
    println!("Download a file from the server");

    // Retrieve the current directory map.
    let dir_map = get_current_directory_map()
        .ok_or_else(|| anyhow!("Unable to access current directory map."))?;

    if dir_map.files.is_empty() {
        note("Error", "No folders available for downloading.")?;
        pause();
        return Ok(());
    }

    let mut items = Vec::new();
    for (file_name, _) in dir_map.files.iter() {
        items.push((file_name.clone(), file_name.clone(), ""));
    }

    let selected_file = select("Select a file to download:")
        .items(&items)
        .interact()?;

    // Attempt to download the file and display the result.
    match download_file(&selected_file) {
        Ok(_) => {
            note("Success", format!("File '{}' has been successfully downloaded.", selected_file))?;
        },
        Err(err) => {
            note("Error", err.to_string())?;
        }
    }

    pause();
    Ok(())
}

fn delete_file_menu() -> Result<()> {
    clear_console();
    println!("Delete a file from the server");

    // Retrieve the current directory map, or return an error message if it's unavailable.
    let dir_map = get_current_directory_map()
        .ok_or_else(|| anyhow!("Unable to access current directory map."))?;

    // Check if there are any files in the directory map. If not, show an error message and return.
    if dir_map.files.is_empty() {
        note("Error", "No files available for deleting.")?;
        pause();
        return Ok(());
    }

    // Create a vector to store the items for the file selection menu.
    let mut items = Vec::new();

    // Populate the items vector with file names and their corresponding labels.
    for (file_name, _) in dir_map.files.iter() {
        items.push((file_name.clone(), file_name.clone(), ""));
    }

    // Prompt the user to select a file for deletion.
    let selected_file = select("Select a file to delete:")
        .items(&items)
        .interact()?;

    // Attempt to delete the selected file and handle the result.
    match delete_file(&selected_file) {
        Ok(_) => {
            note("Success", format!("File '{}' has been successfully deleted.", selected_file))?;
        },
        Err(err) => {
            note("Error", err.to_string())?;
        }
    }

    pause();
    Ok(())
}

fn change_password_menu() -> Result<()> {
    clear_console();
    intro("Change Password")?;

    // Prompt for the new password and validate input.
    let new_password: String = password("Enter your new password:")
        .mask('*')
        .interact()?;

    // Clone the new password for validation.
    let password_clone = new_password.clone();

    // Prompt for password confirmation and validate input.
    password("Confirm your new password:")
        .mask('*')
        .validate(move |input: &String| {
            if *input != password_clone {
                Err("Passwords do not match.")
            } else {
                Ok(())
            }
        })
        .interact()?;

    // Create a spinner to show progress during password change.
    let mut spinner = spinner();
    spinner.start("Changing password...");

    // Attempt to change the user's password and handle the result.
    let (master_password_hash, protected_symmetric_key) = match change_password(&new_password) {
        Ok(val) => val,
        Err(err) => {
            spinner.stop(format!("Failed to change password: {}", err.to_string().as_str()));
            return Err(err);
        }
    };

    // Call the change_password_endpoint and display the result.
    match change_password_endpoint(&get_username().unwrap(), master_password_hash, protected_symmetric_key) {
        Ok(_) => {
            spinner.stop("Password has been successfully changed.");
        },
        Err(err) => {
            spinner.stop(format!("Error changing password: {}", err.to_string().as_str()));
        }
    }

    pause();
    Ok(())
}

fn share_folder_menu() -> Result<()> {
    clear_console();
    intro("Share a folder")?;

    // Retrieve the current directory map.
    let dir_map = get_current_directory_map()
        .ok_or_else(|| anyhow!("Unable to access current directory map."))?;

    let mut folder_items = Vec::new();

    // Populate folder_items with folders that can be shared.
    for (folder_name, _) in dir_map.folders.iter() {
        folder_items.push((folder_name.clone(), folder_name, ""));
    }

    if folder_items.is_empty() {
        note("Error", "No folders available for sharing.")?;
        pause();
        return Ok(());
    }

    // Prompt the user to select a folder for sharing.
    let selected_folder = select("Select a folder:")
        .items(&folder_items)
        .interact()?;

    // Get the current username.
    let current_username = get_username().unwrap();

    // Retrieve the list of users that the folder can be shared with.
    let mut users = list_users_endpoint()?;
    users.retain(|user| *user != current_username);

    let mut directory_metadata;
    let encrypted_folder_name;
    let mut symmetric_key;
    let owner;

    if *dir_map.sharing_state.get(&selected_folder).unwrap() {
        // If the folder is already shared, retrieve the sharing information.
        let user_shares = get_shares().unwrap();
        let share = user_shares.iter().find(|share| share.encrypted_name == get_current_directory_map_folder_value(&selected_folder).unwrap()).unwrap();
        let mut parts = share.path.split('/').collect::<Vec<&str>>();
        owner = parts.first().cloned().unwrap_or_default().to_string();
        parts.pop();
        parts.pop();
        let path = parts.join("/") + "/";

        directory_metadata = read_directory_metadata_endpoint(&path).unwrap();
        encrypted_folder_name = (*share.path.split('/')
            .collect::<Vec<&str>>()
            .get(share.path.split('/').count().saturating_sub(2))
            .unwrap().to_string()).parse()?;
        symmetric_key = decrypt_rsa_oaep(&get_private_key().unwrap(), &share.protected_symmetric_key)?;
    } else {
        // If the folder is not shared, retrieve the current directory metadata and key.
        directory_metadata = get_current_directory_metadata().unwrap();
        encrypted_folder_name = get_current_directory_map_folder_value(&selected_folder).unwrap();
        symmetric_key = get_last_folder_key_chain().unwrap();
        owner = directory_metadata.owner.clone();

        if let Some(folder) = directory_metadata.folders.iter_mut()
            .find(|f| f.name == encrypted_folder_name) {
            symmetric_key = decrypt_xchacha20_poly1305(&symmetric_key, &folder.protected_symmetric_key)?;
        }
    }

    // Remove users that already have access to the folder.
    users.retain(|user| *user != owner);

    if let Some(folder) = directory_metadata.folders.iter_mut()
        .find(|f| f.name == encrypted_folder_name) {
        for share in folder.shares.iter() {
            users.retain(|user| *user != share.username);
        }
    }

    if users.is_empty() {
        note("Error", "No users available for sharing.")?;
        pause();
        return Ok(());
    }

    // Create user_items for selecting a user to share with.
    let user_items: Vec<(String, String, &str)> = users.into_iter().map(|user| (user.clone(), user, "")).collect();

    // Prompt the user to select a user to share the folder with.
    let selected_user = select("Select a user to share with:")
        .items(&user_items)
        .interact()?;

    // Attempt to share the folder and display the result.
    match share_folder(&selected_user, &selected_folder, &encrypted_folder_name, &mut directory_metadata, symmetric_key) {
        Ok(_) => {
            note("Success", "Folder shared successfully")?;
        },
        Err(err) => {
            note("Error", err.to_string())?;
        }
    }

    pause();
    Ok(())
}

pub fn unshare_folder_menu() -> Result<()> {
    clear_console();
    intro("Unshare a folder")?;

    // Retrieve the current directory map.
    let mut dir_map = get_current_directory_map()
        .ok_or_else(|| anyhow!("Unable to access current directory map."))?;

    // Retrieve the current directory metadata.
    let directory_metadata = get_current_directory_metadata().unwrap();

    let mut folder_items = Vec::new();

    // Populate folder_items with folders that can be unshared.
    for (folder_name, encrypted_name) in dir_map.folders.iter() {
        if directory_metadata.folders.iter()
            .any(|f| f.name == *encrypted_name && !f.shares.is_empty()) ||
            *dir_map.sharing_state.get(folder_name).unwrap_or(&false) {
            folder_items.push((folder_name.clone(), folder_name.clone(), "".to_string()));
        }
    }

    if folder_items.is_empty() {
        note("Error", "No folders available for unsharing.")?;
        pause();
        return Ok(());
    }

    // Prompt the user to select a folder to unshare.
    let selected_folder = select("Select a folder:")
        .items(&folder_items)
        .interact()?;

    let mut directory_metadata;
    let encrypted_folder_name;

    if *dir_map.sharing_state.get(&selected_folder).unwrap() {
        // If the folder is already shared, retrieve the sharing information.
        let user_shares = get_shares().unwrap();
        let share = user_shares.iter().find(|share| share.encrypted_name == get_current_directory_map_folder_value(&selected_folder).unwrap()).unwrap();
        let mut parts = share.path.split('/').collect::<Vec<&str>>();
        parts.pop();
        parts.pop();
        let path = parts.join("/") + "/";
        directory_metadata = read_directory_metadata_endpoint(&(path + "/")).unwrap();
        encrypted_folder_name = (*share.path.split('/')
            .collect::<Vec<&str>>()
            .get(share.path.split('/').count().saturating_sub(2))
            .unwrap().to_string()).parse()?;
        dir_map.sharing_state.remove(&selected_folder);
        dir_map.folders.remove(&selected_folder);
    } else {
        // If the folder is not shared, retrieve the current directory metadata.
        directory_metadata = get_current_directory_metadata().unwrap();
        encrypted_folder_name = get_current_directory_map_folder_value(&selected_folder).unwrap();
    }

    // Attempt to unshare the folder and display the result.
    match unshare_folder(&encrypted_folder_name, &mut directory_metadata) {
        Ok(_) => {
            set_current_directory_map(Some(dir_map));
            note("Success", "Folder unshared successfully")?;
        },
        Err(err) => {
            note("Error", err.to_string())?;
        }
    }

    pause();
    Ok(())
}
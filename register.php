<?php
// Include config file
require_once "config.php";
 
// Define variables and initialize with empty values
$username = $password = $confirm_password = "";
$username_err = $password_err = $confirm_password_err = "";
 
// Processing form data when form is submitted
if($_SERVER["REQUEST_METHOD"] == "POST"){
 
    // Validate username
    if(empty(trim($_POST["username"]))){
        $username_err = "Please enter a username.";
    } else{
        // Prepare a select statement
        $sql = "SELECT id FROM users WHERE username = ?";
        
        if($stmt = mysqli_prepare($link, $sql)){
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "s", $param_username);
            
            // Set parameters
            $param_username = trim($_POST["username"]);
            
            // Attempt to execute the prepared statement
            if(mysqli_stmt_execute($stmt)){
                /* store result */
                mysqli_stmt_store_result($stmt);
                
                if(mysqli_stmt_num_rows($stmt) == 1){
                    $username_err = "This username is already taken.";
                } else{
                    $username = trim($_POST["username"]);
                }
            } else{
                echo "Oops! Something went wrong. Please try again later.";
            }

            // Close statement
            mysqli_stmt_close($stmt);
        }
    }
    
    // Validate password
    if(empty(trim($_POST["password"]))){
        $password_err = "Please enter a password.";     
    } elseif(strlen(trim($_POST["password"])) < 6){
        $password_err = "Password must have atleast 6 characters.";
    } else{
        $password = trim($_POST["password"]);
    }
    
    // Validate confirm password
    if(empty(trim($_POST["confirm_password"]))){
        $confirm_password_err = "Please confirm password.";     
    } else{
        $confirm_password = trim($_POST["confirm_password"]);
        if(empty($password_err) && ($password != $confirm_password)){
            $confirm_password_err = "Password did not match.";
        }
    }
    
    // Check input errors before inserting in database
    if(empty($username_err) && empty($password_err) && empty($confirm_password_err)){
        
        // Prepare an insert statement
        $sql = "INSERT INTO users (username, password) VALUES (?, ?)";
         
        if($stmt = mysqli_prepare($link, $sql)){
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "ss", $param_username, $param_password);
            
            // Set parameters
            $param_username = $username;
            $param_password = password_hash($password, PASSWORD_DEFAULT); // Creates a password hash
            
            // Attempt to execute the prepared statement
            if(mysqli_stmt_execute($stmt)){
                // Redirect to login page
                header("location: login.php");
            } else{
                echo "Something went wrong. Please try again later.";
            }

            // Close statement
            mysqli_stmt_close($stmt);
        }
    }
    
    // Close connection
    mysqli_close($link);
}
?>
 <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sign Up</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Segoe+UI:wght@400;600&display=swap');
        * {
            font-family: 'Segoe UI', sans-serif;
        }
    </style>
</head>
<body class="bg-[#7072aa47] flex items-center justify-center h-screen">
    <div class="flex w-[900px] h-[550px] rounded-xl overflow-hidden bg-white shadow-lg">
        <!-- Left Section with Image -->
        <div class="w-1/2 bg-white flex items-center justify-center p-5">
            <div class="w-full h-full bg-[url('Blogging-pana.svg')] bg-contain bg-center bg-no-repeat"></div>
        </div>
        
        <!-- Right Section with Form -->
        <div class="w-1/2 bg-[#36270f] flex items-center justify-center p-10 text-white relative">
            <div class="w-full max-w-[320px]">
                <h2 class="text-2xl font-bold mb-2">Sign Up</h2>
                <p class="text-sm mb-5">Please fill this form to create an account.</p>
                
                <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
                    <!-- Username Field -->
                    <div class="mb-4">
                        <label class="block text-sm mt-3">Username</label>
                        <input type="text" name="username" 
                               class="w-full px-3 py-2 mt-1 rounded-md text-black focus:outline-none focus:ring-2 focus:ring-[#ff6b81] <?php echo (!empty($username_err)) ? 'border-2 border-red-500' : ''; ?>" 
                               value="<?php echo $username; ?>">
                        <?php if (!empty($username_err)): ?>
                            <span class="text-red-400 text-xs"><?php echo $username_err; ?></span>
                        <?php endif; ?>
                    </div>
                    
                    <!-- Password Field -->
                    <div class="mb-4">
                        <label class="block text-sm mt-3">Password</label>
                        <input type="password" name="password" 
                               class="w-full px-3 py-2 mt-1 rounded-md text-black focus:outline-none focus:ring-2 focus:ring-[#ff6b81] <?php echo (!empty($password_err)) ? 'border-2 border-red-500' : ''; ?>" 
                               value="<?php echo $password; ?>">
                        <?php if (!empty($password_err)): ?>
                            <span class="text-red-400 text-xs"><?php echo $password_err; ?></span>
                        <?php endif; ?>
                    </div>
                    
                    <!-- Confirm Password Field -->
                    <div class="mb-6">
                        <label class="block text-sm mt-3">Confirm Password</label>
                        <input type="password" name="confirm_password" 
                               class="w-full px-3 py-2 mt-1 rounded-md text-black focus:outline-none focus:ring-2 focus:ring-[#ff6b81] <?php echo (!empty($confirm_password_err)) ? 'border-2 border-red-500' : ''; ?>" 
                               value="<?php echo $confirm_password; ?>">
                        <?php if (!empty($confirm_password_err)): ?>
                            <span class="text-red-400 text-xs"><?php echo $confirm_password_err; ?></span>
                        <?php endif; ?>
                    </div>
                    
                    <!-- Submit Button -->
                    <button type="submit" class="w-full py-3 bg-[#ff6b81] text-white font-bold rounded-full mt-5 hover:bg-[#ff4757] transition duration-300 focus:outline-none focus:ring-2 focus:ring-[#ff4757] focus:ring-opacity-50">
                        Submit
                    </button>
                    
                    <!-- Reset Button -->
                    <button type="reset" class="w-full py-3 bg-gray-600 text-white font-bold rounded-full mt-3 hover:bg-gray-700 transition duration-300 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-opacity-50">
                        Reset
                    </button>
                    
                    <!-- Login Link -->
                    <p class="text-xs mt-4">
                        Already have an account? 
                        <a href="login.php" class="text-[#dcdde1] underline font-bold">Login here</a>.
                    </p>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
<?php
            $link = mysqli_connect("localhost", "root", "", "multiblog");
            if($link === false)
            {
                die("error: could not connect". mysqli_connect_error());
            }
            $sql = "INSERT INTO contact_form(name, email, subject, message) VALUES (?,?,?,?)";
            if($stmt = mysqli_prepare ($link, $sql))
            {
            mysqli_stmt_bind_param($stmt, "ssss", $name, $email, $subject, $message);
                $name = $_POST['name'];
                $email = $_POST['email'];
                $subject = $_POST['subject'];
                $message = $_POST['message'];
                

                mysqli_stmt_execute($stmt);
                header("location: contact.php");
                // echo "RECORD INSERTED SUCCESSFULLY: <br> <br>$first_name <br> <br>$last_name <br><br> $email <br> <br>$regd_id <br><br> $section <br><br> $department <br><br> $address <br><br> $mobile_no <br> <br>$year_of_joining  ";
            }
            else
            {
                echo "error: could not connect $sql." . mysqli_error($link);
    
            }
            mysqli_stmt_close($stmt);
            mysqli_close ($link);
?>
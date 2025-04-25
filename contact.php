<?php
// Initialize the session
session_start();
 
// Check if the user is logged in, if not then redirect him to login page
if(!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true){
    header("location: login.php");
    exit;
}
?>
<!doctype html>
<html lang="en">

<head>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>MutliLanguage Blogging Platform</title>
   
   <link href="//fonts.googleapis.com/css2?family=Poppins:ital,wght@0,300;0,400;0,700;1,400;1,600&display=swap" rel="stylesheet">
   
   <link rel="stylesheet" href="assets/css/style-starter.css">
</head>

<body>

<header id="site-header" class="fixed-top">
    <div class="container">
        <nav class="navbar navbar-expand-lg navbar-light stroke py-lg-0">
            <h1><a class="navbar-brand pe-xl-5 pe-lg-4" href="index.php">
                    <span class="sublog">Multiligno</span>Blog
                </a></h1>
            <button class="navbar-toggler collapsed" type="button" data-bs-toggle="collapse"
                data-bs-target="#navbarScroll" aria-controls="navbarScroll" aria-expanded="false"
                aria-label="Toggle navigation">
                <span class="navbar-toggler-icon fa icon-expand fa-bars"></span>
                <span class="navbar-toggler-icon fa icon-close fa-times"></span>
            </button>

            <div class="collapse navbar-collapse" id="navbarScroll">
                <ul class="navbar-nav me-lg-auto my-2 my-lg-0 navbar-nav-scroll">
                    <li class="nav-item">
                        <a class="nav-link active" aria-current="page" href="index.php">Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="about.php">Blogs</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="services.php">Services</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="contact.php">Contact</a>
                    </li>
                </ul>

                <ul class="navbar-nav search-right mt-lg-0 mt-2">
                    <li class="nav-item" title="Search"><a href="#search" class="search-search">
                            <span class="fas fa-search" aria-hidden="true"></span></a></li>
                    <li class="nav-item me-lg-3">
                        <a href="#" class="phone-btn btn btn-primary btn-style d-none d-lg-block btn-style ms-2">Sign Up</a>
                    </li>
                </ul>

                <!-- Google Translate Dropdown -->
                <div class="google-translate me-lg-3 d-flex align-items-center">
                    <label class="me-2">Translate:</label>
                    <div id="google_translate_element"></div>
                </div>

                <!-- Search Popup -->
                <div id="search" class="w3lpop-overlay">
                    <div class="w3lpopup">
                        <form action="#formsearch" method="GET" class="d-sm-flex">
                            <input class="form-control me-2" type="search" placeholder="Search here..." required="">
                            <button class="btn btn-style btn-primary" type="submit">Search</button>
                            <a class="close" href="#formsearch">&times;</a>
                        </form>
                    </div>
                </div>
            </div>
        </nav>
    </div>
</header>

<!-- Google Translate Script -->
<script type="text/javascript">
    function googleTranslateElementInit() {
        new google.translate.TranslateElement({
            pageLanguage: 'en',
            includedLanguages: 'en,hi,fr,es,ta,bn,gu,zh-CN,de,ar,ru,pt,ja',
            layout: google.translate.TranslateElement.InlineLayout.SIMPLE
        }, 'google_translate_element');
    }
</script>

<script type="text/javascript"
    src="//translate.google.com/translate_a/element.js?cb=googleTranslateElementInit"></script>

<!-- Optional CSS to clean up Google Translate UI -->
<style>
    .goog-logo-link,
    .goog-te-gadget span {
        display: none !important;
    }

    .goog-te-gadget {
        font-size: 0;
    }

    .goog-te-banner-frame.skiptranslate {
        display: none !important;
    }

    body {
        top: 0px !important;
    }
</style>

    <!--//breadcrumb-->
    <!-- contact1 -->
    <section class="w3l-contact-1 py-5" id="contact">
        <div class="contacts-9 py-lg-5 py-md-4">
            <div class="container">
                <div class="row contact-view">
                    <div class="col-lg-5 cont-details pe-lg-5">
                        <div class="contactct-fm-text text-left">
                            <h6 class="title-subhny">Say Hello</h6>
                            <h3 class="title-w3l mb-2">Get In Touch
                            </h3>
                            <p class="mb-sm-5 mb-4">Start working with Us that can provide everything you need to generate awareness,
                                drive traffic,
                                connect.We guarantee that you’ll be able to have any issue resolved within 24 hours.</p>
                            <div class="cont-top">
                                <div class="cont-left text-center">
                                    <span class="fas fa-phone-alt"></span>
                                </div>
                                <div class="cont-right">
                                    <h5>Phone number</h5>
                                    <p><a href="tel:+(91) 7667250734">+(91) 7667250734</a></p>
                                </div>
                            </div>
                            <div class="cont-top margin-up">
                                <div class="cont-left text-center">
                                    <span class="fas fa-envelope-open-text"></span>
                                </div>
                                <div class="cont-right">
                                    <h5>Send Email</h5>
                                    <p><a href="mailto:DigitMarkrting@mail.com" class="mail">mansisingh6201@gmail.com</a></p>
                                </div>
                            </div>
                            <div class="cont-top margin-up">
                                <div class="cont-left text-center">
                                    <span class="fas fa-map-marker-alt"></span>
                                </div>
                                <div class="cont-right">
                                    <h5>Office Address</h5>
                                    <p class="pr-lg-5">Lovely Professional University<br> Phagwara, Punjab - 144411.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-7 cont-details mt-lg-0 mt-5">
                        <div class="map-content-9">
                            <div class="map-iframe">
                            <iframe src="https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d3408.2677204814445!2d75.59880587560374!3d31.3239786743046!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x391a5bc7dd7e7875%3A0xc22c54913f41e12a!2sapps%2Fwebsite%20development!5e0!3m2!1sen!2sin!4v1744963059371!5m2!1sen!2sin" width="600" height="450" style="border:0;" allowfullscreen="" loading="lazy" referrerpolicy="no-referrer-when-downgrade"></iframe>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>
    <!-- /contact1 -->
    <!-- contact2 -->
    <section class="w3l-contact-1 w3hny-form-btm py-5" id="contact">
        <div class="contacts-9 py-lg-5 py-md-4">
            <div class="container">
                <div class="header-sec text-center mb-5">
                    <h6 class="title-subhny mb-2">Write Us</h6>
                    <h3 class="title-w3l">
                        Don't hesitate to contact us <br> anytime with questions
                    </h3>
                </div>
                <div class="contactct-fm map-content-9">
                    <form action="contact_form.php" class="pt-lg-4" method="post">
                        <div class="twice-two">
                            <input type="text" class="form-control" name="name" id="w3lName" placeholder="Name" required="">
                            <input type="email" class="form-control" name="email" id="w3lSender" placeholder="Email" required="">
                            <input type="text" class="form-control" name="subject" id="w3lSubject" placeholder="Subject" required="">
                        </div>

                        <textarea name="message" class="form-control" id="w3lMessage" placeholder="Message" required=""></textarea>
                        <div class="text-lg-center">
                            <button type="submit" class="btn btn-primary btn-style mt-lg-5 mt-4">Send Message</button>
                        </div>
                    </form>
                </div>


            </div>
        </div>
    </section>
    <!-- /contact2 -->
    <!-- footer -->
    <section class="w3l-footer-29-main">
    <div class="footer-29 py-5">
        <div class="container py-lg-4">
            <div class="row footer-top-29">
                <!-- Branding & About -->
                <div class="col-lg-4 col-md-6 footer-list-29 footer-1 pe-lg-5">
                    <div class="footer-logo mb-4">
                        <h2><a class="navbar-brand" href="index.php">
                                <span class="sublog">PolyLingua</span>Blog
                            </a></h2>
                    </div>
                    <p>PolyLinguaBlog empowers writers and readers from around the world with multilingual support, cultural diversity, and seamless language switching for blogs.</p>
                    <div class="w3l-two-buttons mt-4">
                        <a href="#get-started" class="btn btn-primary btn-style">Get Started</a>
                    </div>
                    <div class="main-social-footer-29 mt-5">
                        <a href="#facebook" class="facebook"><span class="fab fa-facebook-f"></span></a>
                        <a href="#twitter" class="twitter"><span class="fab fa-twitter"></span></a>
                        <a href="#instagram" class="instagram"><span class="fab fa-instagram"></span></a>
                        <a href="#linkedin" class="linkedin"><span class="fab fa-linkedin-in"></span></a>
                    </div>
                </div>

                <!-- Navigation Links -->
                <div class="col-lg-2 col-md-6 footer-list-29 footer-2 mt-sm-0 mt-5">
                    <ul>
                        <h6 class="footer-title-29">Navigate</h6>
                        <li><a href="about.php">About Us</a></li>
                        <li><a href="blog.php">Blog Posts</a></li>
                        <li><a href="dashboard.php">Dashboard</a></li>
                        <li><a href="ratings.php">Ratings</a></li>
                        <li><a href="contact.php">Contact Us</a></li>
                    </ul>
                </div>

                <!-- Features -->
                <div class="col-lg-2 col-md-6 footer-list-29 footer-3 mt-lg-0 mt-5">
                    <h6 class="footer-title-29">Features</h6>
                    <ul>
                        <li><a href="#multi-language">Multi-language Blogs</a></li>
                        <li><a href="#translate">Auto Translation</a></li>
                        <li><a href="#rate">Rating System</a></li>
                        <li><a href="#editor">Rich Text Editor</a></li>
                        <li><a href="#filter">Language Filters</a></li>
                        <li><a href="#community">Global Community</a></li>
                    </ul>
                </div>

                <!-- Resources -->
                <div class="col-lg-2 col-md-6 footer-list-29 footer-4 mt-lg-0 mt-5">
                    <h6 class="footer-title-29">Resources</h6>
                    <ul>
                        <li><a href="#docs">Documentation</a></li>
                        <li><a href="#faq">FAQ</a></li>
                        <li><a href="#guides">User Guides</a></li>
                        <li><a href="#blog-tips">Blogging Tips</a></li>
                        <li><a href="#privacy">Privacy Policy</a></li>
                        <li><a href="#terms">Terms of Use</a></li>
                    </ul>
                </div>

                <!-- Support -->
                <div class="col-lg-2 col-md-6 footer-list-29 footer-4 mt-lg-0 mt-5">
                    <h6 class="footer-title-29">Support</h6>
                    <ul>
                        <li><a href="#help">Help Center</a></li>
                        <li><a href="#feedback">Give Feedback</a></li>
                        <li><a href="#bug">Report a Bug</a></li>
                        <li><a href="#contributors">Contributors</a></li>
                        <li><a href="#support-team">Support Team</a></li>
                        <li><a href="#updates">Platform Updates</a></li>
                    </ul>
                </div>
            </div>
        </div>
    </div>

    <!-- copyright -->
    <section class="w3l-copyright text-center">
        <div class="container">
            <p class="copy-footer-29">© 2025 PolyLinguaBlog. All rights reserved. Crafted with care for global voices.</p>
        </div>

        <!-- move top -->
        <button onclick="topFunction()" id="movetop" title="Go to top">
            <span class="fas fa-arrow-up"></span>
        </button>
        <script>
            window.onscroll = function () {
                scrollFunction()
            };

            function scrollFunction() {
                if (document.body.scrollTop > 20 || document.documentElement.scrollTop > 20) {
                    document.getElementById("movetop").style.display = "block";
                } else {
                    document.getElementById("movetop").style.display = "none";
                }
            }

            function topFunction() {
                document.body.scrollTop = 0;
                document.documentElement.scrollTop = 0;
            }
        </script>
        <!-- /move top -->
    </section>
</section>

    <!-- //footer -->
    <!-- Js scripts -->
    <!-- Template JavaScript -->
    <script src="assets/js/jquery-3.3.1.min.js"></script>
    <script src="assets/js/theme-change.js"></script>
    <!-- MENU-JS -->
    <script>
        $(window).on("scroll", function() {
            var scroll = $(window).scrollTop();

            if (scroll >= 80) {
                $("#site-header").addClass("nav-fixed");
            } else {
                $("#site-header").removeClass("nav-fixed");
            }
        });

        //Main navigation Active Class Add Remove
        $(".navbar-toggler").on("click", function() {
            $("header").toggleClass("active");
        });
        $(document).on("ready", function() {
            if ($(window).width() > 991) {
                $("header").removeClass("active");
            }
            $(window).on("resize", function() {
                if ($(window).width() > 991) {
                    $("header").removeClass("active");
                }
            });
        });

    </script>
    <!-- //MENU-JS -->

    <!-- disable body scroll which navbar is in active -->
    <script>
        $(function() {
            $('.navbar-toggler').click(function() {
                $('body').toggleClass('noscroll');
            })
        });

    </script>
    <!-- //disable body scroll which navbar is in active -->

    <!-- //bootstrap -->
    <script src="assets/js/bootstrap.min.js"></script>

</body>

</html>

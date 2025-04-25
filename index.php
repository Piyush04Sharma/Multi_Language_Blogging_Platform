
<!doctype html>
<html lang="en">

<head>
   
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
                        <a class="nav-link active" aria-current="page" href="afterlogin.php">Home</a>
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
                        <a href="login.php" class="phone-btn btn btn-primary btn-style d-none d-lg-block btn-style ms-2">Login</a>
                    </li>
                </ul>

                <!-- Google Translate Dropdown -->
                <div class="google-translate me-lg-3 d-flex align-items-center">
                <label class="me-2">Multilanguage:</label>
                    <div id="google_translate_element"></div>
                </div>

                <!-- Search Popup -->
                <div id="search" class="w3lpop-overlay">
                   <!-- Multilingual Blog Search Form -->
<div class="w3lpopup">
    <form action="search.php" method="GET" class="d-sm-flex">
        <!-- Language Selector -->
        <select name="lang" class="form-select me-2" required>
            <option value="" disabled selected>Select Language</option>
            <option value="en">English</option>
            <option value="hi">Hindi</option>
            <option value="fr">French</option>
            <option value="es">Spanish</option>
        </select>

        <!-- Search Field -->
        <input class="form-control me-2" name="query" type="search" placeholder="Search here..." required>

        <!-- Submit Button -->
        <button class="btn btn-style btn-primary" type="submit">Search</button>

        <!-- Close Button (optional popup close) -->
        <a class="close" href="#formsearch">&times;</a>
    </form>
</div>

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


<section class="w3l-main-content" id="home">
    <div class="container">
        <div class="row align-items-center w3l-slider-grids">
            <div class="col-lg-6 w3l-slider-left-info pe-lg-5">
                <h6 class="title-subhny mb-2">Welcome to</h6>
                <h3 class="mb-2 title"> <span>Your</span> Global </h3>
                <h3 class="mb-4 title">Multilingual Blogging Platform</h3>
                <p class="w3banr-p">Create, share, and discover content in multiple languages with ease. Join a community of writers and readers worldwide.</p>
                <div class="w3l-buttons mt-sm-5 mt-4">
                    <a class="btn btn-primary btn-style me-2" href="about.php">Learn More</a>
                    <a class="btn btn-outline-primary btn-style" href="contact.php">Get Started</a>
                </div>
            </div>
            <div class="col-lg-6 w3l-slider-right-info mt-lg-0 mt-5 ps-lg-5 align-items-center">
                <div class="w3l-main-slider banner-slider">
                    <div class="slider-info">
                        <div class="w3l-slidehny-img banner-top1">
                            <img src="assets/images/multilingual-blogging.jpg" alt="Multilingual Blogging" class="radius-image img-fluid">
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</section>

    <!-- /main-slider -->
<section class="w3l-grids-3 py-5">
    <div class="container py-md-5 py-3">
        <div class="row align-items-center">
            <div class="col-lg-6 header-sec">
                <h6 class="title-subhny mb-2">Create & Connect</h6>
                <h3 class="title-w3l">
                    Expand your reach with a Multilanguage Blog.
                </h3>
            </div>
            <div class="col-lg-6 header-sec-paraw3 ps-lg-4">
                <p class="">Empower your voice to be heard around the world. Write blogs in your native language or connect with readers through multilingual content — all on one powerful platform.</p>
            </div>
        </div>
        <div class="row bottom_grids text-left mt-lg-5 align-items-center">
            <div class="col-lg-4 col-md-6 mt-5">
                <div class="grid-block">
                    <a href="#features" class="d-block">
                        <div class="grid-block-infw3">
                            <div class="grid-block-icon"><span class="fas fa-language"></span></div>
                            <h4 class="my-3">Multilanguage Support</h4>
                        </div>
                        <p class="">Write and publish your blogs in multiple languages effortlessly. Reach a global audience in the language they understand best.</p>
                    </a>
                </div>
            </div>
            <div class="col-lg-4 col-md-6 mt-5">
                <div class="grid-block active">
                    <a href="#features" class="d-block">
                        <div class="grid-block-infw3">
                            <div class="grid-block-icon"><span class="fas fa-user-friends"></span></div>
                            <h4 class="my-3">User-Friendly Design</h4>
                        </div>
                        <p class="">Enjoy a clean, intuitive interface whether you're reading or writing. Custom dashboards make blogging smooth and enjoyable.</p>
                    </a>
                </div>
            </div>
            <div class="col-lg-4 col-md-6 mt-5">
                <div class="grid-block">
                    <a href="#features" class="d-block">
                        <div class="grid-block-infw3">
                            <div class="grid-block-icon"><span class="fas fa-chart-line" aria-hidden="true"></span></div>

                            <h4 class="my-3">SEO Ready</h4>
                        </div>
                        <p class="">Maximize your content’s visibility with built-in SEO tools tailored for multilingual indexing and better reach on search engines.</p>
                    </a>
                </div>
            </div>
        </div>
    </div>
</section>

<section class="w3l-circles-sec" id="circle">
    <div class="midd-w3 py-5">
        <div class="container py-lg-5 py-3">
            <!--/row-2-->
            <div class="w3l-circles">
                <div class="w3l-circles-infhny">
                    <div class="title-content text-left">
                        <h6 class="title-subhny mb-2">Empowering Global Voices</h6>
                        <h3 class="title-w3l two">Multilingual Blogging for a Connected World</h3>
                    </div>
                    <p class="mt-md-4 mt-3">
                        Create, connect, and communicate beyond borders. Our innovative blogging platform allows you to write and publish content in multiple languages, making it easier than ever to reach and engage a diverse, international audience. Whether you're a beginner or a seasoned writer, share your voice with the world in the language that speaks to your readers.
                    </p>
                </div>
            </div>
            <!--//row-2-->
        </div>
    </div>
</section>

   
<section class="w3l-img-grids" id="gridsimg">
    <div class="blog py-5" id="classes">
        <div class="container py-lg-5">
            <div class="row align-items-center">

                <!-- Feature 1 -->
                <div class="col-lg-4 col-md-6 item mt-lg-0 mt-5">
                    <div class="w3img-grids-info">
                        <div class="w3img-grids-info-gd position-relative">
                            <a href="#services">
                                <div class="page">
                                    <div class="photobox photobox_triangular photobox_scale-rotated">
                                        <div class="photobox__previewbox media-placeholder">
                                            <img class="img-fluid photobox__preview media-placeholder__media radius-image" src="assets/images/g1.jpg" alt="">
                                        </div>
                                        <div class="photobox__info-wrapper">
                                            <div class="photobox__info"><span>Localization</span></div>
                                        </div>
                                    </div>
                                </div>
                            </a>
                            <div class="w3img-grids-info-gd-content mt-4">
                                <a href="#gridsimg" class="titile-img d-block">
                                    <h4 class="mb-2">Multilingual Reach</h4>
                                </a>
                                <p class="">Write blogs in your native language or switch seamlessly between multiple languages to reach a global audience. Our platform supports effortless localization for wider impact.</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Feature 2 -->
                <div class="col-lg-4 col-md-6 item mt-lg-0 mt-5">
                    <div class="w3img-grids-info">
                        <div class="w3img-grids-info-gd position-relative">
                            <a href="#services">
                                <div class="page">
                                    <div class="photobox photobox_triangular photobox_scale-rotated">
                                        <div class="photobox__previewbox media-placeholder">
                                            <img class="img-fluid photobox__preview media-placeholder__media radius-image" src="assets/images/g2.jpg" alt="">
                                        </div>
                                        <div class="photobox__info-wrapper">
                                            <div class="photobox__info"><span>Ease of Use</span></div>
                                        </div>
                                    </div>
                                </div>
                            </a>
                            <div class="w3img-grids-info-gd-content mt-4">
                                <a href="#gridsimg" class="titile-img d-block">
                                    <h4 class="mb-2">Intuitive Editor</h4>
                                </a>
                                <p class="">Our user-friendly editor allows you to create stunning blog posts effortlessly. Format text, insert media, and manage content in any language with just a few clicks.</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Feature 3 -->
                <div class="col-lg-4 col-md-6 item mt-lg-0 mt-5">
                    <div class="w3img-grids-info">
                        <div class="w3img-grids-info-gd position-relative">
                            <a href="#services">
                                <div class="page">
                                    <div class="photobox photobox_triangular photobox_scale-rotated">
                                        <div class="photobox__previewbox media-placeholder">
                                            <img class="img-fluid photobox__preview media-placeholder__media radius-image" src="assets/images/g3.jpg" alt="">
                                        </div>
                                        <div class="photobox__info-wrapper">
                                            <div class="photobox__info"><span>Integration</span></div>
                                        </div>
                                    </div>
                                </div>
                            </a>
                            <div class="w3img-grids-info-gd-content mt-4">
                                <a href="#gridsimg" class="titile-img d-block">
                                    <h4 class="mb-2">Global Tools</h4>
                                </a>
                                <p class="">Easily integrate translation APIs, SEO tools, analytics, and social sharing to optimize visibility and performance of your multilingual blog across all platforms.</p>
                            </div>
                        </div>
                    </div>
                </div>

            </div>
        </div>
    </div>
</section>


    <section class="w3l-video" id="video">
    <div class="video-mid-w3 py-5">
        <div class="container py-md-5 py-3">
            <!--/row-1-->
            <div class="row">
                <div class="col-lg-6 mt-lg-0 mb-5 align-self pe-lg-3">
                    <div class="title-content text-left">
                        <h6 class="title-subhny mb-2">Blog Smarter</h6>
                        <h3 class="title-w3l two">Power your voice in every language</h3>
                    </div>
                    <p class="mt-md-4 mt-3">
                        Our multilingual blogging platform helps creators share their stories globally. From real-time translation to user ratings and personalized dashboards—everything is built for impactful content creation.
                    </p>
                    <div class="w3l-two-buttons">
                        <a href="about.php" class="btn btn-style btn-primary mt-lg-5 mt-4">Explore Features</a>
                        <a href="#contact" class="btn btn-style btn-white mt-lg-5 mt-4 ms-2">Get In Touch</a>
                    </div>
                </div>
                <div class="col-lg-6 videow3-right ps-lg-5">
                    <div class="w3l-index5 py-5">
                        <div class="history-info align-self text-center py-5 my-lg-5">
                            <div class="position-relative py-5">
                                <a href="#small-dialog1" class="popup-with-zoom-anim play-view text-center position-absolute">
                                    <span class="video-play-icon">
                                        <span class="fa fa-play"></span>
                                    </span>
                                </a>
                                <!-- dialog itself, mfp-hide class is required to make dialog hidden -->
                                <div id="small-dialog1" class="zoom-anim-dialog mfp-hide">
                                    <iframe src="https://www.youtube.com/embed/YOUR_VIDEO_ID" frameborder="0" allow="autoplay; fullscreen" allowfullscreen></iframe>
                                </div>
                                <!-- end dialog -->
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!--//row-1-->
        </div>
    </div>
</section>

    
    <section class="w3l-products w3l-faq-block py-5" id="projects">
    <div class="container py-md-5 py-2">
        <div class="header-secw3 text-center mb-5">
           <h3 class="title-w3l mb-4">Ask Your Questions</h3>
        </div>
        <div class="row">
            <div class="col-lg-6 mx-auto pe-lg-5">
                <div class="w3hny-business-img">
                    <img src="assets/images/searching.webp" alt="FAQs for Multilingual Blog Platform" class="img-fluid radius-image">
                </div>
            </div>
            <div class="col-lg-6 mt-lg-0 mt-sm-5 mt-4">
                <div class="accordion">
                    <div class="accordion-item">
                        <button id="accordion-button-1" aria-expanded="true">
                            <span class="accordion-title">How does the multilingual feature work?</span>
                            <span class="icon" aria-hidden="true"></span>
                        </button>
                        <div class="accordion-content">
                            <p>Our platform allows users to write blogs in multiple languages. Readers can switch languages instantly, and machine translation is available for supported languages.</p>
                        </div>
                    </div>
                    <div class="accordion-item">
                        <button id="accordion-button-2" aria-expanded="false">
                            <span class="accordion-title">Can I rate and review blogs?</span>
                            <span class="icon" aria-hidden="true"></span>
                        </button>
                        <div class="accordion-content">
                            <p>Yes, registered users can rate blog posts and leave reviews. This helps surface quality content and gives feedback to the authors.</p>
                        </div>
                    </div>
                    <div class="accordion-item">
                        <button id="accordion-button-3" aria-expanded="false">
                            <span class="accordion-title">Is there a dashboard to manage my blogs?</span>
                            <span class="icon" aria-hidden="true"></span>
                        </button>
                        <div class="accordion-content">
                            <p>Absolutely. Every user gets a personalized dashboard to create, edit, publish, or delete their blogs. Analytics for views and ratings are also available.</p>
                        </div>
                    </div>
                    <div class="accordion-item">
                        <button id="accordion-button-4" aria-expanded="false">
                            <span class="accordion-title">Is the platform free to use?</span>
                            <span class="icon" aria-hidden="true"></span>
                        </button>
                        <div class="accordion-content">
                            <p>Yes, our core blogging features are completely free. Premium features such as advanced analytics or custom domains may be offered in the future.</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</section>

<section class="w3l-clients" id="clients">
    <!-- /grids -->
    <div class="cusrtomer-layout py-5">
        <div class="container py-lg-5 py-md-3">
            <!-- /grids -->
            <div class="testimonial-width">
                <div class="item">
                    <div class="testimonial-content">
                        <div class="testimonial">
                            <blockquote>
                                <i class="fas fa-quote-left"></i>
                                <q>This multilingual blogging platform helped me reach readers around the world. The interface is clean, the language switch is seamless, and the blog rating system gives real feedback. Highly recommended for content creators!</q>
                            </blockquote>
                            <div class="testi-des">
                                <div class="peopl align-self">
                                    <h3>Sarah Martinez</h3>
                                    <p class="indentity">Content Creator, Barcelona</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
     
    </div>
    
</section>

    <section class="w3l-project-main">
        <div class="container">
            <div class="w3l-project py-md-5 py-4">
                <div class="row py-5 align-items-center">
                    <div class="col-lg-6 w3l-project-right">
                        <div class="bottom-info">
                            <div class="header-section pr-lg-5">
                                <h6 class="title-subhny mb-2">Stay Update!</h6>
                                <h3 class="title-w3l">Subscribe to our MultiLinguistic Platform
                                </h3>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-6 w3l-project-left">
                        <form action="email.php" method="post" class="subscribe-wthree mt-lg-5 mt-4">
                            <div class="flex-wrap subscribe-wthree-field">
                                <input class="form-control" type="email" placeholder="Your Email Address" name="email" required="">
                                <button class="btn btn-style btn-primary" type="submit">Subscribe</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </section>
    <!--//w3l-project-->
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
     <script src="assets/js/jquery-1.9.1.min.js"></script>
    <!-- faq -->
    <script>
        const items = document.querySelectorAll(".accordion button");

        function toggleAccordion() {
            const itemToggle = this.getAttribute('aria-expanded');

            for (i = 0; i < items.length; i++) {
                items[i].setAttribute('aria-expanded', 'false');
            }

            if (itemToggle == 'false') {
                this.setAttribute('aria-expanded', 'true');
            }
        }

        items.forEach(item => item.addEventListener('click', toggleAccordion));

    </script>
    <!-- //faq -->
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

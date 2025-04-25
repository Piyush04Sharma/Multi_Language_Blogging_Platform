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

                <!-- <ul class="navbar-nav search-right mt-lg-0 mt-2">
                     <li class="nav-item" title="Search"><a href="#search" class="search-search">
                            <span class="fas fa-search" aria-hidden="true"></span></a></li> 
                    <li class="nav-item me-lg-3">
                        <a href="#" class="phone-btn btn btn-primary btn-style d-none d-lg-block btn-style ms-2">Sign Up</a>
                    </li>
                </ul> -->

                <!-- Google Translate Dropdown -->
                <div class="google-translate me-lg-3 d-flex align-items-center">
                <label class="me-2">Multilanguage:</label>
                    <div id="google_translate_element"></div>
                </div>

                <!-- Search Popup -->
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

    <!--//Header-->
    <!-- breadcrumb -->
    <section class="w3l-about-breadcrumb">
        <div class="breadcrumb-bg breadcrumb-bg-about">
            <div class="container py-lg-5 py-sm-4">
                <div class="w3breadcrumb-gids text-center">
                    <div class="w3breadcrumb-info mt-5">
                        <h2 class="w3ltop-title pt-4">Blogs</h2>
                        <ul class="breadcrumbs-custom-path">
                            <li><a href="index.php">Home</a></li>
                            <li class="active"><span class="fas fa-angle-double-right mx-2"></span> Blog </li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </section>
    <!--//breadcrumb-->
    <!-- feature with photo1 -->
    <section class="w3l-feature-with-photo-1">
    <div class="feature-with-photo-hny py-5">
        <div class="container py-lg-5">
            <div class="feature-with-photo-content">
                <div class="ab-in-flow row mb-lg-5 mb-3">

                    <div class="col-lg-7 ab-right pl-lg-5">
                        <h6 class="title-subhny mb-2"><span>Blogs</span></h6>
                        <h3 class="title-w3l mb-4">Empowering Brands Through Smart Digital Marketing Strategies</h3>
                        <p class="mt-4">
                            At DigitMarketing, we specialize in delivering cutting-edge digital marketing solutions tailored to boost your online presence and drive real results. From SEO and content marketing to paid ads and social media campaigns, we blend creativity with data to help brands grow in the digital landscape.
                        </p>
                        <p class="mt-3">
                            Our team of experts is passionate about innovation and stays ahead of the trends to ensure your business thrives in the competitive online marketplace. Whether you're a startup or an established enterprise, we're here to elevate your digital strategy.
                        </p>

                        <div class="w3l-buttons mt-sm-5 mt-4">
                            <a class="btn btn-primary btn-style me-2" href="about.php">Learn More</a>
                            <a class="btn btn-outline-primary btn-style mr-2" href="services.php">Our Services</a>
                        </div>
                    </div>
                    <div class="col-lg-5 ab-left ps-lg-5">
                   <img src="assets/images/languangeMulti.jpg" class="img-fluid radius-image" alt="Our Digital Marketing Team" style="width: 600px; height: auto;">


                    </div>
                </div>

            </div>
        </div>
    </div>
</section>
<section class="w3l-products py-5" id="blogs">
  <div class="container py-lg-5 py-md-4 py-2">
    <div class="header-sec mx-auto text-center">
      <h6 class="title-subhny mb-2 text-primary">From Our Community</h6>
      <h3 class="title-w3l mb-5">Explore our latest <br>multilanguage blog posts</h3>
    </div>

    <div class="row g-5">

      <!-- Blog 1 -->
      <div class="col-lg-6">
        <div class="blog-post p-4 border rounded shadow-sm h-100">
          <img src="assets/images/global-writing.jpg" class="img-fluid radius-image mb-3" alt="Global Writing Tips">
          <h4 class="blog-title">Tips for Writing in Multiple Languages</h4>
          <p>Discover best practices for writing multilingual content that connects. From tone adjustments to language-specific expressions, enhance your global communication.</p>
          <ul class="w3l-right-book">
            <li><i class="fa fa-check text-success me-2"></i>Multilingual tone guide</li>
            <li><i class="fa fa-check text-success me-2"></i>Writing without losing meaning</li>
            <li><i class="fa fa-check text-success me-2"></i>Inclusive language tips</li>
            <li><i class="fa fa-check text-success me-2"></i>Cultural sensitivity in content</li>
          </ul>
          <a href="blog1.html" class="btn btn-style mt-3">Read More</a>
        </div>
      </div>

      <!-- Blog 2 -->
      <div class="col-lg-6">
        <div class="blog-post p-4 border rounded shadow-sm h-100">
          <img src="assets/images/translation-tech.jpg" class="img-fluid radius-image mb-3" alt="Translation Tech">
          <h4 class="blog-title">AI Translation Tools: What Works?</h4>
          <p>We explore the latest AI translation tools helping bloggers reach wider audiences with more accuracy and speed. See how these tools impact content quality.</p>
          <ul class="w3l-right-book">
            <li><i class="fa fa-check text-success me-2"></i>Real-time language switching</li>
            <li><i class="fa fa-check text-success me-2"></i>Best tools comparison</li>
            <li><i class="fa fa-check text-success me-2"></i>Human vs machine translation</li>
            <li><i class="fa fa-check text-success me-2"></i>Ethical AI usage</li>
          </ul>
          <a href="blog2.html" class="btn btn-style mt-3">Read More</a>
        </div>
      </div>

      <!-- Blog 3 -->
      <div class="col-lg-6">
        <div class="blog-post p-4 border rounded shadow-sm h-100">
          <img src="assets/images/cultural-trends.jpg" class="img-fluid radius-image mb-3" alt="Cultural Trends">
          <h4 class="blog-title">Trending Topics in Different Cultures</h4>
          <p>See what’s hot across languages—from K-drama reviews in Korean to sustainability debates in German. Our community shares what's trending locally and globally.</p>
          <ul class="w3l-right-book">
            <li><i class="fa fa-check text-success me-2"></i>Culture-based blogging</li>
            <li><i class="fa fa-check text-success me-2"></i>Regional content curation</li>
            <li><i class="fa fa-check text-success me-2"></i>Global-local perspective</li>
            <li><i class="fa fa-check text-success me-2"></i>Multicultural voices</li>
          </ul>
          <a href="blog3.html" class="btn btn-style mt-3">Read More</a>
        </div>
      </div>

      <!-- Blog 4 -->
      <div class="col-lg-6">
        <div class="blog-post p-4 border rounded shadow-sm h-100">
          <img src="assets/images/community-stories.jpg" class="img-fluid radius-image mb-3" alt="Community Stories">
          <h4 class="blog-title">Community Voices: Stories in Native Tongues</h4>
          <p>We spotlight diverse bloggers who write in their native language, preserving authenticity and expression. Read inspiring stories from all over the world.</p>
          <ul class="w3l-right-book">
            <li><i class="fa fa-check text-success me-2"></i>Blogger spotlights</li>
            <li><i class="fa fa-check text-success me-2"></i>Language identity & pride</li>
            <li><i class="fa fa-check text-success me-2"></i>Local storytelling</li>
            <li><i class="fa fa-check text-success me-2"></i>Native expressions preserved</li>
          </ul>
          <a href="blog4.html" class="btn btn-style mt-3">Read More</a>
        </div>
      </div>

      <!-- Blog 5 -->
      <div class="col-lg-6">
        <div class="blog-post p-4 border rounded shadow-sm h-100">
          <img src="assets/images/language-learning.jpg" class="img-fluid radius-image mb-3" alt="Language Learning">
          <h4 class="blog-title">How Blogging Helps Language Learning</h4>
          <p>Blogging in a new language can improve fluency, vocabulary, and confidence. Learn how creators are using blogs as tools for language practice.</p>
          <ul class="w3l-right-book">
            <li><i class="fa fa-check text-success me-2"></i>Boost fluency via writing</li>
            <li><i class="fa fa-check text-success me-2"></i>Peer feedback advantage</li>
            <li><i class="fa fa-check text-success me-2"></i>Content as language journal</li>
            <li><i class="fa fa-check text-success me-2"></i>Encouraging multilingual expression</li>
          </ul>
          <a href="blog5.html" class="btn btn-style mt-3">Read More</a>
        </div>
      </div>

      <!-- Blog 6 -->
      <div class="col-lg-6">
        <div class="blog-post p-4 border rounded shadow-sm h-100">
          <img src="assets/images/localization-strategy.jpg" class="img-fluid radius-image mb-3" alt="Localization Strategy">
          <h4 class="blog-title">Localization Strategies for Bloggers</h4>
          <p>Tailoring your blog for different audiences? Learn the strategies behind effective localization—from visuals to cultural tone and translation consistency.</p>
          <ul class="w3l-right-book">
            <li><i class="fa fa-check text-success me-2"></i>Visual & text localization</li>
            <li><i class="fa fa-check text-success me-2"></i>Geo-targeted content planning</li>
            <li><i class="fa fa-check text-success me-2"></i>Local SEO strategies</li>
            <li><i class="fa fa-check text-success me-2"></i>Translation consistency tips</li>
          </ul>
          <a href="blog6.html" class="btn btn-style mt-3">Read More</a>
        </div>
      </div>

    </div>
  </div>
</section>

    <!--/progress-->
    <section class="w3l-servicesblock w3l-servicesblock1 py-5" id="progress">
    <div class="container py-lg-5 py-md-4 py-2">
        <div class="row">
            <div class="col-lg-6 mb-lg-0 mb-5 pe-lg-5">
                <h6 class="title-subhny mb-2">Platform Highlights</h6>
                <h3 class="title-w3l">Powering Global Voices with Multilanguage Blogs</h3>
                <p class="mt-md-4 mt-3">Our platform empowers creators to publish content in multiple languages, ensuring every voice is heard globally. Discover diverse perspectives, express freely in your native tongue, and connect across cultures with our advanced blog features.</p>
            </div>

            <div class="col-lg-6 align-self pe-lg-4">
                <div class="progress-info info1">
                    <h6 class="progress-tittle">Multilanguage Support <span class="">95%</span></h6>
                    <div class="progress">
                        <div class="progress-bar progress-bar-striped bg-success" role="progressbar" style="width:95%" aria-valuenow="95" aria-valuemin="0" aria-valuemax="100">
                        </div>
                    </div>
                </div>
                <div class="progress-info info1">
                    <h6 class="progress-tittle">Real-time Translation Tools <span class="">85%</span></h6>
                    <div class="progress">
                        <div class="progress-bar progress-bar-striped bg-info" role="progressbar" style="width:85%" aria-valuenow="85" aria-valuemin="0" aria-valuemax="100">
                        </div>
                    </div>
                </div>
                <div class="progress-info info2">
                    <h6 class="progress-tittle">Cultural Content Curation <span class="">80%</span></h6>
                    <div class="progress">
                        <div class="progress-bar progress-bar-striped bg-warning" role="progressbar" style="width:80%" aria-valuenow="80" aria-valuemin="0" aria-valuemax="100">
                        </div>
                    </div>
                </div>
                <div class="progress-info info3">
                    <h6 class="progress-tittle">User Engagement Across Languages <span class="">90%</span></h6>
                    <div class="progress">
                        <div class="progress-bar progress-bar-striped bg-danger" role="progressbar" style="width:90%" aria-valuenow="90" aria-valuemin="0" aria-valuemax="100">
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</section>

    
<div class="w3l-team-main py-5" id="blog-types">
  <div class="container py-md-5 py-3">
    <!-- Header -->
    <div class="header-secw3 text-center mb-4">
      <h6 class="title-subhny mb-2">Our Blog Categories</h6>
      <h3 class="title-w3l mb-3">Explore Different Blog Types</h3>
    </div>

    <div class="row w3ls_team_grids text-center">
      <!-- Category 1 -->
      <div class="col-md-3 col-6 w3_agile_team_grid mb-4">
        <div class="box4 p-4">
          <a href="blog5.html" class="d-block mb-3">
            <i class="fas fa-language fa-3x text-primary"></i>
          </a>
          <div class="box-content">
            <h3 class="title">Language Learning</h3>
            <ul class="icon list-inline">
              <li class="list-inline-item"><a href="blog5.html"><i class="fas fa-arrow-right"></i></a></li>
            </ul>
          </div>
        </div>
        <h4><a href="blog5.html" class="title-head">How Blogging Enhances Fluency</a></h4>
        <p class="small">Use your blog as a daily language practice journal.</p>
      </div>

      <!-- Category 2 -->
      <div class="col-md-3 col-6 w3_agile_team_grid mb-4">
        <div class="box4 p-4">
          <a href="blog2.html" class="d-block mb-3">
            <i class="fas fa-robot fa-3x text-success"></i>
          </a>
          <div class="box-content">
            <h3 class="title">AI Translation</h3>
            <ul class="icon list-inline">
              <li class="list-inline-item"><a href="blog2.html"><i class="fas fa-arrow-right"></i></a></li>
            </ul>
          </div>
        </div>
        <h4><a href="blog2.html" class="title-head">Top AI Tools Compared</a></h4>
        <p class="small">DeepL vs Google Translate vs others: which wins?</p>
      </div>

      <!-- Category 3 -->
      <div class="col-md-3 col-6 w3_agile_team_grid mb-4">
        <div class="box4 p-4">
          <a href="blog3.html" class="d-block mb-3">
            <i class="fas fa-globe fa-3x text-warning"></i>
          </a>
          <div class="box-content">
            <h3 class="title">Cultural Trends</h3>
            <ul class="icon list-inline">
              <li class="list-inline-item"><a href="blog3.html"><i class="fas fa-arrow-right"></i></a></li>
            </ul>
          </div>
        </div>
        <h4><a href="blog3.html" class="title-head">What’s Trending Worldwide</a></h4>
        <p class="small">From K-dramas to eco-living—see global hot topics.</p>
      </div>

      <!-- Category 4 -->
      <div class="col-md-3 col-6 w3_agile_team_grid mb-4">
        <div class="box4 p-4">
          <a href="blog4.html" class="d-block mb-3">
            <i class="fas fa-comments fa-3x text-danger"></i>
          </a>
          <div class="box-content">
            <h3 class="title">Community Voices</h3>
            <ul class="icon list-inline">
              <li class="list-inline-item"><a href="blog4.html"><i class="fas fa-arrow-right"></i></a></li>
            </ul>
          </div>
        </div>
        <h4><a href="blog4.html" class="title-head">Stories in Native Tongues</a></h4>
        <p class="small">Real stories shared in authors’ mother tongues.</p>
      </div>
    </div>
  </div>
</div>

    
    <section class="w3l-project-main">
    <div class="container">
        <div class="w3l-project py-md-5 py-4">
            <div class="row py-5 align-items-center">
                <div class="col-lg-8 w3l-project-right">
                    <div class="bottom-info">
                        <div class="header-section pr-lg-5">
                            <h6 class="title-subhny mb-2">Global Blogging</h6>
                            <h3 class="title-w3l">Start Sharing Your Voice <br>In Any Language!</h3>
                        </div>
                    </div>
                </div>
                <div class="col-lg-4 w3l-project-left about-w3page-btns mt-lg-0 mt-4">
                    <div class="w3l-buttons d-sm-flex">
                        <a class="btn btn-primary btn-style me-2" href="about.php">Explore Features</a>
                        <a class="btn btn-outline-primary btn-style" href="contact.php">Get In Touch</a>
                    </div>
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
                // When the user scrolls down 20px from the top of the document, show the button
                window.onscroll = function() {
                    scrollFunction()
                };

                function scrollFunction() {
                    if (document.body.scrollTop > 20 || document.documentElement.scrollTop > 20) {
                        document.getElementById("movetop").style.display = "block";
                    } else {
                        document.getElementById("movetop").style.display = "none";
                    }
                }

                // When the user clicks on the button, scroll to the top of the document
                function topFunction() {
                    document.body.scrollTop = 0;
                    document.documentElement.scrollTop = 0;
                }

            </script>
            <!-- /move top -->
        </section>
        <!-- //copyright -->
    </section>
    <!-- //footer -->
    <!-- Js scripts -->
    <!-- Template JavaScript -->
    <script src="assets/js/jquery-3.3.1.min.js"></script>
    <script src="assets/js/theme-change.js"></script>
    <!--/Tabs-->
    <script src="assets/js/jquery-1.9.1.min.js"></script>
    <script src="assets/js/easyResponsiveTabs.js"></script>
    <!--Plug-in Initialisation-->
    <script type="text/javascript">
        $(document).ready(function() {
            //Horizontal Tab
            $('#parentHorizontalTab').easyResponsiveTabs({
                type: 'default', //Types: default, vertical, accordion
                width: 'auto', //auto or any width like 600px
                fit: true, // 100% fit in a container
                tabidentify: 'hor_1', // The tab groups identifier
                activate: function(event) { // Callback function if tab is switched
                    var $tab = $(this);
                    var $info = $('#nested-tabInfo');
                    var $name = $('span', $info);
                    $name.text($tab.text());
                    $info.show();
                }
            });
        });

    </script>
    <!--//Tabs-->
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

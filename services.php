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
   
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>MutliLanguage Blogging Platform</title>
   
    <link href="//fonts.googleapis.com/css2?family=Poppins:ital,wght@0,300;0,400;0,700;1,400;1,600&display=swap" rel="stylesheet">
   
    <link rel="stylesheet" href="assets/css/style-starter.css">
</head>

<body>
    <!--/Header-->
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

<!--/services-->
<section class="w3l-services2" id="services">
    <div id="cwp23-block" class="py-5">
        <div class="container py-lg-5">
            <div class="row cwp23-content mb-lg-5 mb-4">
                <div class="col-lg-6 cwp23-img">
                    <h6 class="title-subhny mb-2">What We Do?</h6>
                    <h3 class="title-w3l mb-4">Create, Share, and Engage! We help you grow your blog.</h3>
                </div>
                <div class="col-lg-6 cwp23-text mt-lg-0 mt-5 ps-lg-5">
                    <br><br>
                    <p class="mb-4">Our platform provides everything you need to create a multilingual blog. We offer intuitive tools to write, publish, 
                        and manage your posts, as well as a seamless experience for both authors and readers across different languages.</p>
                   
                </div>
            </div>
            <div class="row cwp23-content">
                <div class="col-lg-6 cwp23-img">
                    <div class="w3l-market-seo-img">
                        <img src="assets/images/websitelang.jpg" alt="blogging tools" class="img-fluid">
                    </div>
                </div>
                <div class="col-lg-6 cwp23-text mt-lg-0 mt-5 ps-lg-5">
                  
                    <h3 class="title-w3l mb-4">The best blogging tools for your content creation journey</h3>
                    <p class="mb-4">From customizable templates to multilingual support, our platform ensures that you have everything you need to
                         create amazing content and reach a global audience. We offer:</p>
                    <ul>
                        <li>Multilingual blog management</li>
                        <li>Content customization options</li>
                        <li>Reader engagement features</li>
                        <li>SEO tools and optimization</li>
                    </ul>
                    <div class="w3l-buttons mt-sm-5 mt-4">
                        <a class="btn btn-primary btn-style me-2" href="about.php">Explore Features</a>
                        <a class="btn btn-outline-primary btn-style mr-2" href="contact.php">Contact Us</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
</section>
<!--features-->
<section style="background:rgb(242, 243, 243); padding: 60px 20px; color: #333;" id="features">
  <div style="max-width: 1200px;background:rgb(236, 240, 242); margin: 0 auto;">
    <!-- Header -->
    <div style="text-align: center; margin-bottom: 50px;">
      <h3 style="font-size: 36px; font-weight: bold; margin-bottom: 10px;">✨ What We Offer</h3>
      <p style="font-size: 18px; max-width: 700px; margin: 0 auto; color: #666;">Explore our user-friendly rating system to review and rate your favorite blogs.
         Your feedback fuels our future content!</p>
    </div>

    <!-- Feature Boxes -->
    <div style="display: flex; flex-wrap: wrap; justify-content: space-between; gap: 20px;">
      <!-- Box 1 -->
      <div style="flex: 1 1 calc(25% - 20px); min-width: 260px; background: linear-gradient(to bottom right, #facc15, #ca8a04); color: white; padding: 30px; border-radius: 16px; box-shadow: 0 6px 20px rgba(60, 26, 196, 0.1); text-align: center; transition: transform 0.3s, box-shadow 0.3s;" class="feature-box">
        <div style="font-size: 40px; margin-bottom: 15px;">⭐</div>
        <h4 style="font-size: 20px; font-weight: bold; margin-bottom: 10px;">User Ratings</h4>
        <p>Rate blog posts with just a click. 1 to 5 stars, your call!</p>
      </div>

      <!-- Box 2 -->
      <div style="flex: 1 1 calc(25% - 20px); min-width: 260px; background: linear-gradient(to bottom right, #60a5fa, #2563eb); color: white; padding: 30px; border-radius: 16px; box-shadow: 0 6px 20px rgba(4, 0, 216, 0.83); text-align: center; transition: transform 0.3s, box-shadow 0.3s;" class="feature-box">
        <div style="font-size: 40px; margin-bottom: 15px;">👍</div>
        <h4 style="font-size: 20px; font-weight: bold; margin-bottom: 10px;">Rate & Review</h4>
        <p>Share your thoughts. Help others and improve our content!</p>
      </div>

      <!-- Box 3 -->
      <div style="flex: 1 1 calc(25% - 20px); min-width: 260px; background: linear-gradient(to bottom right, #34d399, #059669); color: white; padding: 30px; border-radius: 16px; box-shadow: 0 6px 20px rgba(157, 165, 188, 0.1); text-align: center; transition: transform 0.3s, box-shadow 0.3s;" class="feature-box">
        <div style="font-size: 40px; margin-bottom: 15px;">💬</div>
        <h4 style="font-size: 20px; font-weight: bold; margin-bottom: 10px;">Give Feedback</h4>
        <p>Let us know how we can improve. Feedback is always welcome.</p>
      </div>

      <!-- Box 4 -->
      <div style="flex: 1 1 calc(25% - 20px); min-width: 260px; background: linear-gradient(to bottom right, #f472b6, #db2777); color: white; padding: 30px; border-radius: 16px; box-shadow: 0 6px 20px rgba(55, 80, 135, 0.1); text-align: center; transition: transform 0.3s, box-shadow 0.3s;" class="feature-box">
        <div style="font-size: 40px; margin-bottom: 15px;">⭐½</div>
        <h4 style="font-size: 20px; font-weight: bold; margin-bottom: 10px;">Average Ratings</h4>
        <p>Check out the community's thoughts on blogs you love.</p>
      </div>
    </div>

    <!-- Rating Form -->
    <div style="margin-top: 60px; background:#a7c7e7; padding: 40px; border-radius: 16px; box-shadow: 0 6px 20px rgba(221, 0, 55, 0.86); color: #eee; animation: fadeIn 1.5s ease-out;">
      <h3 style="font-size: 24px; font-weight: 600; text-align: center; margin-bottom: 30px;">🌟 Add Your Rating</h3>
      <form onsubmit="submitRating(event)" style="display: flex; flex-wrap: wrap; gap: 20px;">
        <div style="flex: 1 1 45%; animation: bounceIn 1s ease-in-out;">
          <label for="userName" style="display: block; margin-bottom: 8px;">Your Name</label>
          <input type="text" id="userName" name="userName" placeholder="Enter your name" required style="width: 100%; padding: 12px; border-radius: 8px; border: 2px solid #ccc; transition: transform 0.3s, border 0.3s;">
        </div>

        <div style="flex: 1 1 45%; animation: bounceIn 1s ease-in-out 0.2s;">
          <label for="rating" style="display: block; margin-bottom: 8px;">Your Rating</label>
          <select id="rating" name="rating" required style="width: 100%; padding: 12px; border-radius: 8px; border: 2px solid #ccc; transition: transform 0.3s, border 0.3s;">
            <option value="" disabled selected>Select rating</option>
            <option value="1">⭐ 1 Star</option>
            <option value="2">⭐⭐ 2 Stars</option>
            <option value="3">⭐⭐⭐ 3 Stars</option>
            <option value="4">⭐⭐⭐⭐ 4 Stars</option>
            <option value="5">⭐⭐⭐⭐⭐ 5 Stars</option>
          </select>
        </div>

        <div style="flex: 1 1 100%; animation: bounceIn 1s ease-in-out 0.4s;">
          <label for="userReview" style="display: block; margin-bottom: 8px;">Your Review</label>
          <textarea id="userReview" name="userReview" rows="4" placeholder="Write your review..." required style="width: 100%; padding: 12px; border-radius: 8px; border: 2px solid #ccc; transition: transform 0.3s, border 0.3s;"></textarea>
        </div>

        <div style="flex: 1 1 100%; text-align: center; animation: bounceIn 1s ease-in-out 0.6s;">
          <button type="submit" style="padding: 12px 30px; background: linear-gradient(to right, #ec4899, #f59e0b); color: white; font-weight: bold; border: none; border-radius: 50px; font-size: 18px; cursor: pointer; transition: transform 0.3s, scale 0.2s, background-color 0.3s;">
            Submit Rating
          </button>
        </div>
      </form> 
    </div>
  </div>
</section>

<script>
  function submitRating(event) {
    event.preventDefault();
    const name = document.getElementById('userName').value;
    const rating = document.getElementById('rating').value;
    const review = document.getElementById('userReview').value;

    if (name && rating && review) {
      alert(`Thank you, ${name}! Your ${rating}-star review has been submitted.`);
      // Reset form
      document.getElementById('userName').value = '';
      document.getElementById('rating').value = '';
      document.getElementById('userReview').value = '';
    } else {
      alert("Please fill out all fields.");
    }
  }
</script>

<style>
  /* Hover effect on feature boxes */
  .feature-box:hover {
    transform: scale(1.05); /* Slight scaling */
    box-shadow: 0 12px 40px rgba(0, 0, 0, 0.15); /* Darker shadow effect */
  }

  /* Bouncy Animation */
  @keyframes bounce {
    0% { transform: translateY(0); }
    50% { transform: translateY(-20px); }
    100% { transform: translateY(0); }
  }

  /* Fade-In Animation */
  @keyframes fadeIn {
    0% { opacity: 0; }
    100% { opacity: 1; }
  }

  /* Bounce-in Animation for Form Fields */
  @keyframes bounceIn {
    0% { transform: translateY(30px); opacity: 0; }
    60% { transform: translateY(-10px); opacity: 1; }
    100% { transform: translateY(0); }
  }

  /* Button Hover Effect */
  button:hover {
    transform: scale(1.1);
    background-color: #f59e0b;
  }

  /* Input Field Focus */
  input:focus, textarea:focus, select:focus {
    animation: bounce 0.5s ease-in-out;
    border-color: #ec4899;
  }

  /* Cursor Hover Effect */
  button:hover, input:hover, textarea:hover, select:hover {
    cursor: pointer;
  }

  /* Input and Select Hover */
  input:hover, textarea:hover, select:hover {
    transform: scale(1.02);
  }
</style>


    <!--//features section -->

    <!--/w3l-services-->
    <section class="w3l-services py-5" id="blogs">
  <div class="container py-md-5 py-3 pb-4">

    <div class="title-content mb-5 text-center">
      <h3 class="title-w3l mb-4">Featured Posts</h3>
      <h6 class="title-subhny mb-2">Blog</h6>
    </div>

    <div class="row about-cols">
      <!-- Blog 1 -->
      <div class="col-lg-4 col-md-6 mt-md-0 mt-3 blog-col" data-delay="0.2s">
        <div class="about-col">
          <div class="icon"><i class="fas fa-pen-nib"></i></div>
          <h4 class="title">
            <a href="blog-post-1.html">How to Start a Multilingual Blog</a>
          </h4>
          <p>Learn the step-by-step process to launch your blog in multiple languages, reach a global audience, and manage translations efficiently.</p>
          <div class="rating" data-index="1">
            <span class="star" data-index="1">&#9733;</span>
            <span class="star" data-index="2">&#9733;</span>
            <span class="star" data-index="3">&#9733;</span>
            <span class="star" data-index="4">&#9733;</span>
            <span class="star" data-index="5">&#9733;</span>
          </div>
          <p id="rating-text-1">Rating: 0/5</p>
        </div>
      </div>

      <!-- Blog 2 -->
      <div class="col-lg-4 col-md-6 mt-md-0 mt-3 blog-col" data-delay="0.4s">
        <div class="about-col">
          <div class="icon"><i class="fas fa-globe"></i></div>
          <h4 class="title">
            <a href="blog-post-2.html">Top 10 Translation Tools Compared</a>
          </h4>
          <p>An in-depth comparison of the best free and paid translation services to power your multilingual content strategy.</p>
          <div class="rating" data-index="2">
            <span class="star" data-index="1">&#9733;</span>
            <span class="star" data-index="2">&#9733;</span>
            <span class="star" data-index="3">&#9733;</span>
            <span class="star" data-index="4">&#9733;</span>
            <span class="star" data-index="5">&#9733;</span>
          </div>
          <p id="rating-text-2">Rating: 0/5</p>
        </div>
      </div>

      <!-- Blog 3 -->
      <div class="col-lg-4 col-md-6 mt-md-0 mt-3 blog-col" data-delay="0.6s">
        <div class="about-col">
          <div class="icon"><i class="fas fa-code"></i></div>
          <h4 class="title">
            <a href="blog-post-3.html">SEO Tips for Multilanguage Sites</a>
          </h4>
          <p>Boost your search rankings across different regions and languages with these proven multilanguage SEO techniques.</p>
          <div class="rating" data-index="3">
            <span class="star" data-index="1">&#9733;</span>
            <span class="star" data-index="2">&#9733;</span>
            <span class="star" data-index="3">&#9733;</span>
            <span class="star" data-index="4">&#9733;</span>
            <span class="star" data-index="5">&#9733;</span>
          </div>
          <p id="rating-text-3">Rating: 0/5</p>
        </div>
      </div>

      <!-- Blog 4 -->
      <div class="col-lg-4 col-md-6 mt-md-0 mt-3 blog-col" data-delay="0.8s">
        <div class="about-col">
          <div class="icon"><i class="fas fa-users"></i></div>
          <h4 class="title">
            <a href="blog-post-4.html">Building Community Across Languages</a>
          </h4>
          <p>Discover how to engage readers from diverse linguistic backgrounds and foster a vibrant, inclusive blog community.</p>
          <div class="rating" data-index="4">
            <span class="star" data-index="1">&#9733;</span>
            <span class="star" data-index="2">&#9733;</span>
            <span class="star" data-index="3">&#9733;</span>
            <span class="star" data-index="4">&#9733;</span>
            <span class="star" data-index="5">&#9733;</span>
          </div>
          <p id="rating-text-4">Rating: 0/5</p>
        </div>
      </div>

      <!-- Blog 5 -->
      <div class="col-lg-4 col-md-6 mt-md-0 mt-3 blog-col" data-delay="1s">
        <div class="about-col">
          <div class="icon"><i class="fas fa-mobile-alt"></i></div>
          <h4 class="title">
            <a href="blog-post-5.html">Mobile App for Your Blog</a>
          </h4>
          <p>Turn your multilanguage blog into a native-like mobile experience—best frameworks, tips, and deployment strategies.</p>
          <div class="rating" data-index="5">
            <span class="star" data-index="1">&#9733;</span>
            <span class="star" data-index="2">&#9733;</span>
            <span class="star" data-index="3">&#9733;</span>
            <span class="star" data-index="4">&#9733;</span>
            <span class="star" data-index="5">&#9733;</span>
          </div>
          <p id="rating-text-5">Rating: 0/5</p>
        </div>
      </div>

      <!-- Blog 6 -->
      <div class="col-lg-4 col-md-6 mt-md-0 mt-3 blog-col" data-delay="1.2s">
        <div class="about-col">
          <div class="icon"><i class="far fa-chart-bar"></i></div>
          <h4 class="title">
            <a href="blog-post-6.html">Analytics for Global Audiences</a>
          </h4>
          <p>Measure what matters when your visitors speak different languages—set up goals, funnels, and reports correctly.</p>
          <div class="rating" data-index="6">
            <span class="star" data-index="1">&#9733;</span>
            <span class="star" data-index="2">&#9733;</span>
            <span class="star" data-index="3">&#9733;</span>
            <span class="star" data-index="4">&#9733;</span>
            <span class="star" data-index="5">&#9733;</span>
          </div>
          <p id="rating-text-6">Rating: 0/5</p>
        </div>
      </div>
    </div>
  </div>

  <style>
    .blog-col {
      opacity: 0;
      transform: translateY(20px);
      transition: opacity 0.6s ease, transform 0.6s ease;
    }
    .blog-col.visible {
      opacity: 1;
      transform: translateY(0);
    }
    .about-col {
      background: #fff;
      border-radius: 12px;
      padding: 30px;
      box-shadow: 0 6px 18px rgba(0,0,0,0.1);
      transition: transform 0.3s, box-shadow 0.3s;
    }
    .about-col:hover {
      transform: translateY(-8px);
      box-shadow: 0 12px 24px rgba(0,0,0,0.15);
    }
    .about-col .icon {
      font-size: 2.5rem;
      color: #ff5722;
      margin-bottom: 15px;
      transition: transform 0.3s;
    }
    .about-col:hover .icon {
      transform: rotate(20deg) scale(1.1);
    }
    .about-col .title a {
      color: #333;
      text-decoration: none;
      transition: color 0.3s;
    }
    .about-col .title a:hover {
      color: #ff5722;
    }

    /* Star Rating Styles */
    .rating {
      display: flex;
      justify-content: left;
      gap: 5px;
      cursor: pointer;
      user-select: none;
      margin-top: 10px;
    }
    .star {
      font-size: 1.5rem;
      color: #ddd;
      transition: color 0.3s;
    }
    .star.filled {
      color: #ff5722;
    }
  </style>

  <script>
    window.addEventListener('DOMContentLoaded', () => {
      // entrance
      document.querySelectorAll('.blog-col').forEach((col, i) => {
        setTimeout(() => col.classList.add('visible'), parseFloat(col.dataset.delay) * 1000);
      });

      // interactive rating
      document.querySelectorAll('.rating').forEach((ratingDiv, idx) => {
        const stars = ratingDiv.querySelectorAll('.star');
        const text = document.getElementById(`rating-text-${ratingDiv.dataset.index}`);
        let current = 0;

        stars.forEach((star, i) => {
          star.addEventListener('mouseenter', () => {
            stars.forEach((s, j) => s.classList.toggle('filled', j <= i));
          });
          star.addEventListener('mouseleave', () => {
            stars.forEach((s, j) => s.classList.toggle('filled', j < current));
          });
          star.addEventListener('click', () => {
            current = i + 1;
            text.textContent = `Rating: ${current}/5`;
            stars.forEach((s, j) => s.classList.toggle('filled', j < current));
          });
        });
      });
    });
  </script>
</section>


    <!--//w3l-services-->

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
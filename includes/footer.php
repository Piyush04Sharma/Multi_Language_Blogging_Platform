<?php
/**
 * Footer Include
 * 
 * This file contains the footer HTML that will be included in all pages.
 */

// Include the language configuration and translations if not already included
if (!function_exists('__')) {
    require_once __DIR__ . '/../config/languages.php';
    require_once __DIR__ . '/../config/translations.php';
}
?>
<!-- footer -->
<section class="w3l-footer-29-main">
    <div class="footer-29 py-5">
        <div class="container py-lg-4">
            <div class="row footer-top-29">
                <div class="col-lg-4 col-md-6 footer-list-29 footer-1 pe-lg-5">
                    <div class="footer-logo mb-4">
                        <h2><a class="navbar-brand" href="index.php">
                                <span class="sublog">Multiligno</span>Blog
                            </a></h2>
                    </div>
                    <p><?php echo __('footer_description'); ?></p>
                    <div class="w3l-two-buttons mt-4">
                        <a href="#trail" class="btn btn-primary btn-style"><?php echo __('try_it_free'); ?></a>
                    </div>
                    <div class="main-social-footer-29 mt-5">
                        <a href="#facebook" class="facebook"><span class="fab fa-facebook-f"></span></a>
                        <a href="#twitter" class="twitter"><span class="fab fa-twitter"></span></a>
                        <a href="#instagram" class="instagram"><span class="fab fa-instagram"></span></a>
                        <a href="#linkedin" class="linkedin"><span class="fab fa-linkedin-in"></span></a>
                    </div>
                </div>
                <div class="col-lg-2 col-md-6 footer-list-29 footer-2 mt-sm-0 mt-5">

                    <ul>
                        <h6 class="footer-title-29"><?php echo __('links'); ?></h6>
                        <li><a href="about.php"><?php echo __('about'); ?></a></li>
                        <li><a href="blog.php"><?php echo __('blog_posts'); ?></a></li>
                        <li><a href="services.php"><?php echo __('services'); ?></a></li>
                        <li><a href="contact.php"><?php echo __('contact'); ?></a></li>

                    </ul>
                </div>
                <div class="col-lg-2 col-md-6 footer-list-29 footer-3 mt-lg-0 mt-5">
                    <h6 class="footer-title-29"><?php echo __('services'); ?></h6>
                    <ul>
                        <li><a href="#traning"><?php echo __('web_design'); ?></a></li>
                        <li><a href="#traning"><?php echo __('development'); ?></a></li>
                        <li><a href="#traning"><?php echo __('marketing_plans'); ?></a></li>
                        <li><a href="#marketplace"><?php echo __('digital_services'); ?></a></li>
                        <li><a href="#experts"><?php echo __('email_marketing'); ?></a></li>
                        <li><a href="#platform"><?php echo __('product_selling'); ?></a></li>
                    </ul>

                </div>
                <div class="col-lg-2 col-md-6  footer-list-29 footer-4 mt-lg-0 mt-5">
                    <h6 class="footer-title-29"><?php echo __('more_info'); ?></h6>
                    <ul>
                        <li><a href="#seo"><?php echo __('offline_seo'); ?></a></li>
                        <li><a href="#traning"><?php echo __('development'); ?></a></li>
                        <li><a href="#hack"><?php echo __('growth_hacking'); ?></a></li>
                        <li><a href="#studio"><?php echo __('film_studio'); ?></a></li>
                        <li><a href="#branding"><?php echo __('branding'); ?></a></li>
                        <li><a href="#experts"><?php echo __('email_marketing'); ?></a></li>
                        <li><a href="#marketplace"><?php echo __('lead_generation'); ?></a></li>
                    </ul>
                </div>
                <div class="col-lg-2 col-md-6  footer-list-29 footer-4 mt-lg-0 mt-5">
                    <h6 class="footer-title-29"><?php echo __('support'); ?></h6>
                    <ul>
                        <li><a href="#awards"><?php echo __('awards'); ?></a></li>
                        <li><a href="#secutiry"><?php echo __('security'); ?></a></li>

                        <li><a href="#proj"><?php echo __('products'); ?></a></li>
                        <li><a href="#efaq"><?php echo __('faq'); ?></a></li>
                        <li><a href="#help"><?php echo __('help'); ?></a></li>
                        <li><a href="#mail"><?php echo __('mail_us'); ?></a></li>
                        <li><a href="#terms"><?php echo __('terms'); ?></a></li>
                        <li><a href="#policy"><?php echo __('privacy_policy'); ?></a></li>


                    </ul>
                </div>
            </div>
        </div>
    </div>
    <!-- copyright -->
    <section class="w3l-copyright text-center">
        <div class="container">
            <p class="copy-footer-29">© <?php echo date('Y'); ?> MultilignoBlog. <?php echo __('all_rights_reserved'); ?>. <?php echo __('design_by'); ?> <a href="https://w3layouts.com/" target="_blank">
                    W3Layouts</a></p>
        </div>

        <!-- move top -->
        <button onclick="topFunction()" id="movetop" title="<?php echo __('go_to_top'); ?>">
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
<?php
// Connect to your MySQL database
$conn = new mysqli("localhost", "root", "", "blogdb"); // change credentials as needed
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$query = $_GET['query'] ?? '';
$lang = $_GET['lang'] ?? 'en';

// Sanitize inputs
$query = $conn->real_escape_string($query);
$lang = $conn->real_escape_string($lang);

// Search blog posts where language matches
$sql = "SELECT * FROM blog_posts WHERE language='$lang' 
        AND (title LIKE '%$query%' OR content LIKE '%$query%')";
$result = $conn->query($sql);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <title>Search Results</title>
</head>
<body>

<!-- Google Translate Widget -->
<div style="text-align:right">
    <div id="google_translate_element"></div>
</div>

<script type="text/javascript">
  function googleTranslateElementInit() {
    new google.translate.TranslateElement({
      pageLanguage: 'en',
      includedLanguages: 'en,hi,fr,es',
      layout: google.translate.TranslateElement.InlineLayout.SIMPLE
    }, 'google_translate_element');
  }
</script>
<script src="//translate.google.com/translate_a/element.js?cb=googleTranslateElementInit"></script>

<h2>Search Results for "<?php echo htmlspecialchars($query); ?>" in "<?php echo strtoupper($lang); ?>"</h2>

<?php
if ($result->num_rows > 0) {
    while($row = $result->fetch_assoc()) {
        echo "<div style='border:1px solid #ccc;padding:10px;margin:10px 0'>";
        echo "<h3>" . htmlspecialchars($row['title']) . "</h3>";
        echo "<p>" . nl2br(htmlspecialchars($row['content'])) . "</p>";
        echo "</div>";
    }
} else {
    echo "<p>No results found.</p>";
}

$conn->close();
?>

</body>
</html>

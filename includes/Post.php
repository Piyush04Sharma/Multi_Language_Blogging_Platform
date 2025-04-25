<?php
/**
 * Post Class
 * 
 * This class handles blog posts with multilingual support.
 */

class Post {
    private $db;
    private $id;
    private $user_id;
    private $category_id;
    private $status;
    private $featured_image;
    private $comment_status;
    private $comment_count;
    private $view_count;
    private $created_at;
    private $updated_at;
    private $translations = [];
    
    /**
     * Constructor
     * 
     * @param PDO $db Database connection
     */
    public function __construct($db) {
        $this->db = $db;
    }
    
    /**
     * Create a new post
     * 
     * @param array $data Post data
     * @param array $translations Translations for different languages
     * @return int|bool Post ID on success, false on failure
     */
    public function create($data, $translations) {
        try {
            $this->db->beginTransaction();
            
            // Insert into posts table
            $stmt = $this->db->prepare("
                INSERT INTO posts (user_id, category_id, status, featured_image, comment_status)
                VALUES (:user_id, :category_id, :status, :featured_image, :comment_status)
            ");
            
            $stmt->execute([
                ':user_id' => $data['user_id'],
                ':category_id' => $data['category_id'] ?? null,
                ':status' => $data['status'] ?? 'draft',
                ':featured_image' => $data['featured_image'] ?? null,
                ':comment_status' => $data['comment_status'] ?? 'open'
            ]);
            
            $post_id = $this->db->lastInsertId();
            
            // Insert translations
            foreach ($translations as $lang => $translation) {
                $stmt = $this->db->prepare("
                    INSERT INTO post_translations (post_id, language, title, slug, content, excerpt, meta_title, meta_description)
                    VALUES (:post_id, :language, :title, :slug, :content, :excerpt, :meta_title, :meta_description)
                ");
                
                $stmt->execute([
                    ':post_id' => $post_id,
                    ':language' => $lang,
                    ':title' => $translation['title'],
                    ':slug' => $this->createSlug($translation['title']),
                    ':content' => $translation['content'],
                    ':excerpt' => $translation['excerpt'] ?? null,
                    ':meta_title' => $translation['meta_title'] ?? null,
                    ':meta_description' => $translation['meta_description'] ?? null
                ]);
            }
            
            // Add tags if provided
            if (!empty($data['tags'])) {
                $this->addTags($post_id, $data['tags']);
            }
            
            $this->db->commit();
            return $post_id;
        } catch (Exception $e) {
            $this->db->rollBack();
            error_log("Error creating post: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get a post by ID
     * 
     * @param int $id Post ID
     * @param string $lang Language code
     * @return array|bool Post data on success, false on failure
     */
    public function getById($id, $lang = null) {
        try {
            // Get base post data
            $stmt = $this->db->prepare("
                SELECT p.*, u.username, u.first_name, u.last_name, c.name as category_name, c.slug as category_slug
                FROM posts p
                LEFT JOIN users u ON p.user_id = u.id
                LEFT JOIN categories c ON p.category_id = c.id
                WHERE p.id = :id
            ");
            
            $stmt->execute([':id' => $id]);
            $post = $stmt->fetch();
            
            if (!$post) {
                return false;
            }
            
            // Get translation for the specified language or all translations
            $stmt = $this->db->prepare("
                SELECT * FROM post_translations
                WHERE post_id = :post_id
                " . ($lang ? "AND language = :language" : "")
            );
            
            $params = [':post_id' => $id];
            if ($lang) {
                $params[':language'] = $lang;
            }
            
            $stmt->execute($params);
            $translations = $stmt->fetchAll();
            
            // Add translations to post data
            $post['translations'] = [];
            foreach ($translations as $translation) {
                $post['translations'][$translation['language']] = $translation;
            }
            
            // Get tags
            $stmt = $this->db->prepare("
                SELECT t.* FROM tags t
                JOIN post_tags pt ON t.id = pt.tag_id
                WHERE pt.post_id = :post_id
            ");
            
            $stmt->execute([':post_id' => $id]);
            $post['tags'] = $stmt->fetchAll();
            
            return $post;
        } catch (Exception $e) {
            error_log("Error getting post: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get posts by language
     * 
     * @param string $lang Language code
     * @param array $options Query options (limit, offset, category_id, etc.)
     * @return array|bool Posts data on success, false on failure
     */
    public function getByLanguage($lang, $options = []) {
        try {
            $limit = $options['limit'] ?? 10;
            $offset = $options['offset'] ?? 0;
            $category_id = $options['category_id'] ?? null;
            $status = $options['status'] ?? 'published';
            
            $sql = "
                SELECT p.*, pt.title, pt.slug, pt.excerpt, u.username, u.first_name, u.last_name, 
                       c.name as category_name, c.slug as category_slug
                FROM posts p
                JOIN post_translations pt ON p.id = pt.post_id
                LEFT JOIN users u ON p.user_id = u.id
                LEFT JOIN categories c ON p.category_id = c.id
                WHERE pt.language = :lang AND p.status = :status
            ";
            
            $params = [
                ':lang' => $lang,
                ':status' => $status
            ];
            
            if ($category_id) {
                $sql .= " AND p.category_id = :category_id";
                $params[':category_id'] = $category_id;
            }
            
            $sql .= " ORDER BY p.created_at DESC LIMIT :limit OFFSET :offset";
            $params[':limit'] = $limit;
            $params[':offset'] = $offset;
            
            $stmt = $this->db->prepare($sql);
            $stmt->execute($params);
            $posts = $stmt->fetchAll();
            
            // Get tags for each post
            foreach ($posts as &$post) {
                $stmt = $this->db->prepare("
                    SELECT t.* FROM tags t
                    JOIN post_tags pt ON t.id = pt.tag_id
                    WHERE pt.post_id = :post_id
                ");
                
                $stmt->execute([':post_id' => $post['id']]);
                $post['tags'] = $stmt->fetchAll();
            }
            
            return $posts;
        } catch (Exception $e) {
            error_log("Error getting posts by language: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Update a post
     * 
     * @param int $id Post ID
     * @param array $data Post data
     * @param array $translations Translations for different languages
     * @return bool True on success, false on failure
     */
    public function update($id, $data, $translations) {
        try {
            $this->db->beginTransaction();
            
            // Update posts table
            $stmt = $this->db->prepare("
                UPDATE posts 
                SET category_id = :category_id,
                    status = :status,
                    featured_image = :featured_image,
                    comment_status = :comment_status
                WHERE id = :id
            ");
            
            $stmt->execute([
                ':id' => $id,
                ':category_id' => $data['category_id'] ?? null,
                ':status' => $data['status'] ?? 'draft',
                ':featured_image' => $data['featured_image'] ?? null,
                ':comment_status' => $data['comment_status'] ?? 'open'
            ]);
            
            // Update translations
            foreach ($translations as $lang => $translation) {
                $stmt = $this->db->prepare("
                    INSERT INTO post_translations (post_id, language, title, slug, content, excerpt, meta_title, meta_description)
                    VALUES (:post_id, :language, :title, :slug, :content, :excerpt, :meta_title, :meta_description)
                    ON DUPLICATE KEY UPDATE
                    title = VALUES(title),
                    slug = VALUES(slug),
                    content = VALUES(content),
                    excerpt = VALUES(excerpt),
                    meta_title = VALUES(meta_title),
                    meta_description = VALUES(meta_description)
                ");
                
                $stmt->execute([
                    ':post_id' => $id,
                    ':language' => $lang,
                    ':title' => $translation['title'],
                    ':slug' => $this->createSlug($translation['title']),
                    ':content' => $translation['content'],
                    ':excerpt' => $translation['excerpt'] ?? null,
                    ':meta_title' => $translation['meta_title'] ?? null,
                    ':meta_description' => $translation['meta_description'] ?? null
                ]);
            }
            
            // Update tags if provided
            if (isset($data['tags'])) {
                // Remove existing tags
                $stmt = $this->db->prepare("DELETE FROM post_tags WHERE post_id = :post_id");
                $stmt->execute([':post_id' => $id]);
                
                // Add new tags
                $this->addTags($id, $data['tags']);
            }
            
            $this->db->commit();
            return true;
        } catch (Exception $e) {
            $this->db->rollBack();
            error_log("Error updating post: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Delete a post
     * 
     * @param int $id Post ID
     * @return bool True on success, false on failure
     */
    public function delete($id) {
        try {
            $stmt = $this->db->prepare("DELETE FROM posts WHERE id = :id");
            return $stmt->execute([':id' => $id]);
        } catch (Exception $e) {
            error_log("Error deleting post: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Add tags to a post
     * 
     * @param int $post_id Post ID
     * @param array $tags Array of tag names
     * @return bool True on success, false on failure
     */
    private function addTags($post_id, $tags) {
        try {
            foreach ($tags as $tag_name) {
                // Check if tag exists
                $stmt = $this->db->prepare("SELECT id FROM tags WHERE name = :name");
                $stmt->execute([':name' => $tag_name]);
                $tag = $stmt->fetch();
                
                if (!$tag) {
                    // Create new tag
                    $stmt = $this->db->prepare("
                        INSERT INTO tags (name, slug)
                        VALUES (:name, :slug)
                    ");
                    
                    $stmt->execute([
                        ':name' => $tag_name,
                        ':slug' => $this->createSlug($tag_name)
                    ]);
                    
                    $tag_id = $this->db->lastInsertId();
                } else {
                    $tag_id = $tag['id'];
                }
                
                // Add tag to post
                $stmt = $this->db->prepare("
                    INSERT IGNORE INTO post_tags (post_id, tag_id)
                    VALUES (:post_id, :tag_id)
                ");
                
                $stmt->execute([
                    ':post_id' => $post_id,
                    ':tag_id' => $tag_id
                ]);
            }
            
            return true;
        } catch (Exception $e) {
            error_log("Error adding tags: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Create a URL-friendly slug
     * 
     * @param string $text Text to convert to slug
     * @return string URL-friendly slug
     */
    private function createSlug($text) {
        // Convert text to lowercase
        $text = mb_strtolower($text, 'UTF-8');
        
        // Replace non-alphanumeric characters with hyphens
        $text = preg_replace('/[^a-z0-9-]/', '-', $text);
        
        // Remove multiple consecutive hyphens
        $text = preg_replace('/-+/', '-', $text);
        
        // Remove leading and trailing hyphens
        $text = trim($text, '-');
        
        return $text;
    }
} 
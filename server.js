// server.js
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors());
app.use(express.json());

// Create database connection pool
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'Jxyn9269$',
  database: 'ForumDesk',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Helper function to check if index exists
async function indexExists(connection, indexName, tableName) {
  try {
    const [rows] = await connection.query(
      `SELECT COUNT(1) AS exists_flag 
       FROM INFORMATION_SCHEMA.STATISTICS 
       WHERE table_schema = DATABASE() 
         AND table_name = ? 
         AND index_name = ?`,
      [tableName, indexName]
    );
    return rows[0].exists_flag === 1;
  } catch (error) {
    console.error(`Error checking index ${indexName}:`, error);
    return false;
  }
}

// Create tables if they don't exist
async function initializeDatabase() {
  let connection;
  try {
    connection = await pool.getConnection();
    
    // Create Users table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS Users (
        user_id VARCHAR(50) PRIMARY KEY,
        username VARCHAR(100) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Create Topics table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS Topics (
        topic_id VARCHAR(50) PRIMARY KEY,
        title VARCHAR(200) NOT NULL,
        description TEXT,
        created_by VARCHAR(50) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES Users(user_id) ON DELETE CASCADE
      )
    `);
    
    // Create Posts table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS Posts (
        post_id VARCHAR(50) PRIMARY KEY,
        topic_id VARCHAR(50) NOT NULL,
        user_id VARCHAR(50) NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (topic_id) REFERENCES Topics(topic_id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE
      )
    `);
    
    // Create Comments table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS Comments (
        comment_id INT AUTO_INCREMENT PRIMARY KEY,
        post_id VARCHAR(50) NOT NULL,
        user_id VARCHAR(50) NOT NULL,
        parent_comment_id INT,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (post_id) REFERENCES Posts(post_id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE,
        FOREIGN KEY (parent_comment_id) REFERENCES Comments(comment_id) ON DELETE SET NULL
      )
    `);
    
    // Create Tags table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS Tags (
        tag_id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL UNIQUE
      )
    `);
    
    // Create PostTags table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS PostTags (
        post_id VARCHAR(50) NOT NULL,
        tag_id INT NOT NULL,
        PRIMARY KEY (post_id, tag_id),
        FOREIGN KEY (post_id) REFERENCES Posts(post_id) ON DELETE CASCADE,
        FOREIGN KEY (tag_id) REFERENCES Tags(tag_id) ON DELETE CASCADE
      )
    `);
    
    // Create Votes table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS Votes (
        vote_id INT AUTO_INCREMENT PRIMARY KEY,
        post_id VARCHAR(50),
        comment_id INT,
        user_id VARCHAR(50) NOT NULL,
        vote_type ENUM('up', 'down') NOT NULL,
        voted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (post_id) REFERENCES Posts(post_id) ON DELETE CASCADE,
        FOREIGN KEY (comment_id) REFERENCES Comments(comment_id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE,
        UNIQUE KEY unique_vote (user_id, post_id, comment_id)
      )
    `);
    
    // Create indexes if they don't exist
    const indexes = [
      { name: 'IX_Users_Username', table: 'Users', column: 'username' },
      { name: 'IX_Topics_CreatedAt', table: 'Topics', column: 'created_at' },
      { name: 'IX_Posts_TopicId', table: 'Posts', column: 'topic_id' },
      { name: 'IX_Comments_PostId', table: 'Comments', column: 'post_id' },
      { name: 'IX_Tags_Name', table: 'Tags', column: 'name' },
      { name: 'IX_PostTags_TagId', table: 'PostTags', column: 'tag_id' }
    ];
    
    for (const index of indexes) {
      const exists = await indexExists(connection, index.name, index.table);
      if (!exists) {
        await connection.query(
          `CREATE INDEX ${index.name} ON ${index.table}(${index.column})`
        );
        console.log(`Created index ${index.name} on ${index.table}(${index.column})`);
      }
    }
    
    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Error initializing database:', error);
  } finally {
    if (connection) connection.release();
  }
}

// Initialize database on server start
initializeDatabase();

// Middleware to verify JWT
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    req.user = jwt.verify(token, 'secret_key');
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// User Registration
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) 
    return res.status(400).json({ error: 'All fields are required' });
  
  try {
    // Check if email already exists
    const [existingEmail] = await pool.execute(
      'SELECT * FROM Users WHERE email = ?', 
      [email]
    );
    if (existingEmail.length > 0) 
      return res.status(400).json({ error: 'Email already registered' });
    
    // Check if username already exists (case-insensitive)
    const [existingUsername] = await pool.execute(
      'SELECT * FROM Users WHERE LOWER(username) = LOWER(?)', 
      [username]
    );
    if (existingUsername.length > 0) 
      return res.status(400).json({ error: 'Username already taken' });
    
    // Create user
    const userId = uuidv4();
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.execute(
      'INSERT INTO Users (user_id, username, email, password_hash) VALUES (?, ?, ?, ?)', 
      [userId, username, email, hashedPassword]
    );
    res.status(201).json({ message: 'User registered' });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) 
    return res.status(400).json({ error: 'Email and password are required' });
  
  try {
    const [users] = await pool.execute('SELECT * FROM Users WHERE email = ?', [email]);
    const user = users[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) return res.status(401).json({ error: 'Invalid credentials' });
    
    const token = jwt.sign({ userId: user.user_id }, 'secret_key');
    res.json({ token, userId: user.user_id, username: user.username });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get User Profile
app.get('/api/users/:id', authenticate, async (req, res) => {
  try {
    const [users] = await pool.execute(
      'SELECT user_id, username, email, created_at FROM Users WHERE user_id = ?', 
      [req.params.id]
    );
    if (!users.length) return res.status(404).json({ error: 'User not found' });
    
    // Get user activity stats
    const [topics] = await pool.execute(
      'SELECT COUNT(*) AS count FROM Topics WHERE created_by = ?',
      [req.params.id]
    );
    
    const [posts] = await pool.execute(
      'SELECT COUNT(*) AS count FROM Posts WHERE user_id = ?',
      [req.params.id]
    );
    
    const [comments] = await pool.execute(
      'SELECT COUNT(*) AS count FROM Comments WHERE user_id = ?',
      [req.params.id]
    );
    
    const user = users[0];
    user.topics = topics[0].count;
    user.posts = posts[0].count;
    user.comments = comments[0].count;
    
    res.json(user);
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// Get All Topics
app.get('/api/topics', async (req, res) => {
  try {
    const [rows] = await pool.execute(`
      SELECT 
        t.topic_id, 
        t.title, 
        t.description, 
        u.username AS created_by,
        COUNT(p.post_id) AS post_count,
        MAX(p.created_at) AS last_activity
      FROM Topics t
      LEFT JOIN Posts p ON t.topic_id = p.topic_id
      LEFT JOIN Users u ON t.created_by = u.user_id
      GROUP BY t.topic_id, t.title, t.description, u.username
      ORDER BY last_activity DESC
    `);
    res.json(rows);
  } catch (err) {
    console.error('Error fetching topics:', err);
    res.status(500).json({ error: 'Failed to load topics' });
  }
});

// Get Single Topic
app.get('/api/topics/:id', async (req, res) => {
  try {
    const [topic] = await pool.execute(
      'SELECT t.*, u.username FROM Topics t JOIN Users u ON t.created_by = u.user_id WHERE topic_id = ?', 
      [req.params.id]
    );
    if (!topic.length) return res.status(404).json({ error: 'Topic not found' });
    res.json(topic[0]);
  } catch (err) {
    console.error('Error fetching topic:', err);
    res.status(500).json({ error: 'Failed to load topic' });
  }
});

// Get Posts for Topic
app.get('/api/topics/:id/posts', async (req, res) => {
  try {
    const [posts] = await pool.execute(`
      SELECT 
        p.post_id, 
        p.content, 
        p.created_at,
        u.username,
        u.user_id,
        (SELECT COUNT(*) FROM Comments c WHERE c.post_id = p.post_id) AS comment_count,
        (SELECT COALESCE(SUM(CASE WHEN v.vote_type = 'up' THEN 1 WHEN v.vote_type = 'down' THEN -1 ELSE 0 END), 0) 
         FROM Votes v WHERE v.post_id = p.post_id) AS vote_score
      FROM Posts p
      JOIN Users u ON p.user_id = u.user_id
      WHERE p.topic_id = ?
      ORDER BY p.created_at ASC
    `, [req.params.id]);
    
    // Get tags for each post
    for (const post of posts) {
      const [tags] = await pool.execute(`
        SELECT t.tag_id, t.name 
        FROM PostTags pt
        JOIN Tags t ON pt.tag_id = t.tag_id
        WHERE pt.post_id = ?
      `, [post.post_id]);
      post.tags = tags;
    }
    
    res.json(posts);
  } catch (err) {
    console.error('Error fetching posts:', err);
    res.status(500).json({ error: 'Failed to load posts' });
  }
});

// Create Topic
app.post('/api/topics', authenticate, async (req, res) => {
  const { title, description } = req.body;
  if (!title) return res.status(400).json({ error: 'Title is required' });
  
  try {
    const topicId = uuidv4();
    await pool.execute(
      'INSERT INTO Topics (topic_id, title, description, created_by) VALUES (?, ?, ?, ?)', 
      [topicId, title, description || null, req.user.userId]
    );
    res.status(201).json({ topicId, message: 'Topic created' });
  } catch (err) {
    console.error('Error creating topic:', err);
    res.status(500).json({ error: 'Topic creation failed' });
  }
});

// Create Post
app.post('/api/posts', authenticate, async (req, res) => {
  const { topicId, content, tags } = req.body;
  if (!topicId || !content) 
    return res.status(400).json({ error: 'Topic ID and content are required' });
  
  try {
    const postId = uuidv4();
    await pool.execute(
      'INSERT INTO Posts (post_id, topic_id, user_id, content) VALUES (?, ?, ?, ?)', 
      [postId, topicId, req.user.userId, content]
    );
    
    // Process tags
    if (tags && tags.length > 0) {
      for (const tagName of tags) {
        // Check if tag exists
        const [existingTag] = await pool.execute(
          'SELECT tag_id FROM Tags WHERE name = ?',
          [tagName]
        );
        
        let tagId;
        if (existingTag.length > 0) {
          tagId = existingTag[0].tag_id;
        } else {
          // Create new tag
          const [newTag] = await pool.execute(
            'INSERT INTO Tags (name) VALUES (?)',
            [tagName]
          );
          tagId = newTag.insertId;
        }
        
        // Link tag to post
        await pool.execute(
          'INSERT INTO PostTags (post_id, tag_id) VALUES (?, ?)',
          [postId, tagId]
        );
      }
    }
    
    res.status(201).json({ postId, message: 'Post created' });
  } catch (err) {
    console.error('Error creating post:', err);
    res.status(500).json({ error: 'Post creation failed' });
  }
});

// Get Comments for Post
app.get('/api/posts/:postId/comments', async (req, res) => {
  try {
    const [rows] = await pool.execute(`
      SELECT 
        c.comment_id, 
        c.post_id, 
        c.user_id, 
        c.parent_comment_id, 
        c.content, 
        c.created_at, 
        u.username,
        (SELECT COALESCE(SUM(CASE WHEN v.vote_type = 'up' THEN 1 WHEN v.vote_type = 'down' THEN -1 ELSE 0 END), 0) 
         FROM Votes v WHERE v.comment_id = c.comment_id) AS vote_score
      FROM Comments c 
      JOIN Users u ON c.user_id = u.user_id 
      WHERE c.post_id = ? 
      ORDER BY c.created_at ASC
    `, [req.params.postId]);
    res.json(rows);
  } catch (err) {
    console.error('Error fetching comments:', err);
    res.status(500).json({ error: 'Failed to load comments' });
  }
});

// Create Comment
app.post('/api/comments', authenticate, async (req, res) => {
  const { postId, content, parentCommentId } = req.body;
  if (!postId || !content) 
    return res.status(400).json({ error: 'Post ID and content are required' });
  
  try {
    const [result] = await pool.execute(
      'INSERT INTO Comments (post_id, user_id, content, parent_comment_id) VALUES (?, ?, ?, ?)', 
      [postId, req.user.userId, content, parentCommentId || null]
    );
    res.status(201).json({ commentId: result.insertId, message: 'Comment created' });
  } catch (err) {
    console.error('Error creating comment:', err);
    res.status(500).json({ error: 'Comment creation failed' });
  }
});

// Get All Tags
app.get('/api/tags', async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT * FROM Tags');
    res.json(rows);
  } catch (err) {
    console.error('Error fetching tags:', err);
    res.status(500).json({ error: 'Failed to load tags' });
  }
});

// Handle Voting
app.post('/api/vote', authenticate, async (req, res) => {
  const { postId, commentId, voteType } = req.body;
  
  if (!['up', 'down'].includes(voteType)) 
    return res.status(400).json({ error: 'Invalid vote type' });
  
  if (!postId && !commentId) 
    return res.status(400).json({ error: 'Post or comment ID required' });
  
  try {
    // Determine if voting on a post or comment
    const voteTarget = postId ? 'post' : 'comment';
    const targetId = postId || commentId;
    
    // Check for existing vote
    const [existingVote] = await pool.execute(
      `SELECT vote_id, vote_type FROM Votes 
       WHERE user_id = ? 
         AND ${voteTarget}_id = ?`,
      [req.user.userId, targetId]
    );
    
    if (existingVote.length > 0) {
      const vote = existingVote[0];
      if (vote.vote_type === voteType) {
        // Remove vote
        await pool.execute(
          `DELETE FROM Votes 
           WHERE vote_id = ?`,
          [vote.vote_id]
        );
      } else {
        // Update vote
        await pool.execute(
          `UPDATE Votes SET vote_type = ? 
           WHERE vote_id = ?`,
          [voteType, vote.vote_id]
        );
      }
    } else {
      // Add new vote
      await pool.execute(
        `INSERT INTO Votes (${voteTarget}_id, user_id, vote_type) VALUES (?, ?, ?)`,
        [targetId, req.user.userId, voteType]
      );
    }
    
    // Get updated vote score
    let voteScore;
    if (postId) {
      const [result] = await pool.execute(
        `SELECT 
          SUM(CASE WHEN vote_type = 'up' THEN 1 WHEN vote_type = 'down' THEN -1 ELSE 0 END) AS vote_score 
         FROM Votes 
         WHERE post_id = ?`, 
        [postId]
      );
      voteScore = result[0].vote_score || 0;
    } else {
      const [result] = await pool.execute(
        `SELECT 
          SUM(CASE WHEN vote_type = 'up' THEN 1 WHEN vote_type = 'down' THEN -1 ELSE 0 END) AS vote_score 
         FROM Votes 
         WHERE comment_id = ?`, 
        [commentId]
      );
      voteScore = result[0].vote_score || 0;
    }
    
    res.json({ voteScore });
  } catch (err) {
    console.error('Error processing vote:', err);
    res.status(500).json({ error: 'Voting failed' });
  }
});

app.listen(5000, () => console.log('Server running on port 5000'));
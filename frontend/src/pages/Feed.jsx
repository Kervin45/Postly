import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { API_BASE } from "@/config";

const styles = {
  container: { maxWidth: "800px", margin: "0 auto", padding: "20px" },
  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: "30px",
  },
  title: { color: "#1e293b", margin: 0 },
  logoutBtn: {
    padding: "8px 16px",
    backgroundColor: "#64748b",
    color: "white",
    border: "none",
    borderRadius: "6px",
    cursor: "pointer",
  },
  createPostSection: {
    backgroundColor: "white",
    padding: "20px",
    borderRadius: "12px",
    boxShadow: "0 2px 4px rgba(0,0,0,0.1)",
    marginBottom: "30px",
  },
  textarea: {
    width: "100%",
    padding: "12px",
    border: "1px solid #e2e8f0",
    borderRadius: "8px",
    fontSize: "16px",
    marginBottom: "15px",
    minHeight: "100px",
  },
  postBtn: {
    padding: "12px 24px",
    backgroundColor: "#3b82f6",
    color: "white",
    border: "none",
    borderRadius: "8px",
    cursor: "pointer",
  },
  postsSection: {
    backgroundColor: "white",
    padding: "20px",
    borderRadius: "12px",
    boxShadow: "0 2px 4px rgba(0,0,0,0.1)",
  },
  postCard: {
    borderBottom: "1px solid #e2e8f0",
    padding: "20px 0",
  },
  postActions: { display: "flex", gap: "10px" },
  editBtn: {
    padding: "6px 12px",
    backgroundColor: "#fbbf24",
    color: "white",
    border: "none",
    borderRadius: "4px",
    cursor: "pointer",
  },
  deleteBtn: {
    padding: "6px 12px",
    backgroundColor: "#ef4444",
    color: "white",
    border: "none",
    borderRadius: "4px",
    cursor: "pointer",
  },
};

function Feed() {
  const [newPost, setNewPost] = useState("");
  const [posts, setPosts] = useState([]);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  const token = localStorage.getItem("token");
  const userId = localStorage.getItem("userId");

  useEffect(() => {
    if (!token) {
      navigate("/");
      return;
    }
    fetchPosts();
  }, [token]);

  const fetchPosts = async () => {
    const res = await fetch(`${API_BASE}/posts`);
    const data = await res.json();
    setPosts(data);
  };

  const handleCreatePost = async (e) => {
    e.preventDefault();
    setError("");

    if (!newPost.trim()) {
      setError("Post cannot be empty");
      return;
    }

    const res = await fetch(`${API_BASE}/posts`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ content: newPost }),
    });

    if (res.ok) {
      setNewPost("");
      fetchPosts();
    } else {
      setError("Failed to create post");
    }
  };

  const handleEditPost = async (id, content) => {
    const updated = prompt("Edit post", content);
    if (!updated) return;

    await fetch(`${API_BASE}/posts/${id}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ content: updated }),
    });

    fetchPosts();
  };

  const handleDeletePost = async (id) => {
    if (!window.confirm("Delete post?")) return;

    await fetch(`${API_BASE}/posts/${id}`, {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    fetchPosts();
  };

  const handleLogout = () => {
    localStorage.clear();
    navigate("/");
  };

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <h1>Postly Feed</h1>
        <button onClick={handleLogout}>Logout</button>
      </div>

      <form onSubmit={handleCreatePost}>
        <textarea
          value={newPost}
          onChange={(e) => setNewPost(e.target.value)}
        />
        {error && <p>{error}</p>}
        <button type="submit">Post</button>
      </form>

      {posts.map((post) => (
        <div key={post.id}>
          <p>{post.content}</p>
          {post.user_id === Number(userId) && (
            <>
              <button onClick={() => handleEditPost(post.id, post.content)}>
                Edit
              </button>
              <button onClick={() => handleDeletePost(post.id)}>Delete</button>
            </>
          )}
        </div>
      ))}
    </div>
  );
}

export default Feed;

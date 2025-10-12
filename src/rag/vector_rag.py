#!/usr/bin/env python3
"""
Vector-based RAG for Cyber Threat Assessment

Uses sentence transformers for semantic similarity search over knowledge base.
Replaces keyword/Jaccard retrieval with embedding-based search for better context matching.
"""

import os
import numpy as np
from typing import List, Tuple, Optional
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity


class VectorRAG:
    def __init__(self, model_name: str = "all-MiniLM-L6-v2", kb_path: str = "./HF_Space/knowledge_base"):
        """
        Initialize vector RAG with sentence transformer model.
        
        Args:
            model_name: Sentence transformer model name
            kb_path: Path to knowledge base directory
        """
        self.model_name = model_name
        self.kb_path = kb_path
        self.encoder = None
        self.documents = []
        self.embeddings = None
        self._load_model()
        self._load_documents()
    
    def _load_model(self):
        """Load sentence transformer model."""
        try:
            self.encoder = SentenceTransformer(self.model_name)
            print(f"Loaded sentence transformer: {self.model_name}")
        except Exception as e:
            print(f"Failed to load model {self.model_name}: {e}")
            raise
    
    def _load_documents(self):
        """Load and encode all documents in knowledge base."""
        if not os.path.isdir(self.kb_path):
            print(f"Knowledge base path not found: {self.kb_path}")
            return
        
        documents = []
        for fname in os.listdir(self.kb_path):
            if not fname.lower().endswith((".md", ".txt")):
                continue
            
            fpath = os.path.join(self.kb_path, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read().strip()
                if content:
                    documents.append((fname, content))
            except Exception as e:
                print(f"Error reading {fpath}: {e}")
                continue
        
        if not documents:
            print("No documents found in knowledge base")
            return
        
        self.documents = documents
        print(f"Loaded {len(documents)} documents from knowledge base")
        
        # Encode all documents
        contents = [doc[1] for doc in documents]
        self.embeddings = self.encoder.encode(contents, show_progress_bar=True)
        print(f"Encoded {len(contents)} documents with {self.embeddings.shape[1]} dimensions")
    
    def retrieve(self, query: str, k: int = 3, min_similarity: float = 0.3) -> List[Tuple[str, str, float]]:
        """
        Retrieve most relevant documents for query using semantic similarity.
        
        Args:
            query: Search query
            k: Number of documents to retrieve
            min_similarity: Minimum similarity threshold
            
        Returns:
            List of (filename, content, similarity_score) tuples
        """
        if not self.documents or self.embeddings is None:
            return []
        
        if not query.strip():
            return []
        
        # Encode query
        query_embedding = self.encoder.encode([query])
        
        # Calculate similarities
        similarities = cosine_similarity(query_embedding, self.embeddings)[0]
        
        # Get top-k results above threshold
        results = []
        for i, similarity in enumerate(similarities):
            if similarity >= min_similarity:
                results.append((self.documents[i][0], self.documents[i][1], float(similarity)))
        
        # Sort by similarity and return top-k
        results.sort(key=lambda x: x[2], reverse=True)
        return results[:k]
    
    def retrieve_context(self, query: str, context: str = "", k: int = 3, min_similarity: float = 0.3) -> str:
        """
        Retrieve context string for use in prompts.
        
        Args:
            query: Main search query
            context: Additional context
            k: Number of documents to retrieve
            min_similarity: Minimum similarity threshold
            
        Returns:
            Formatted context string
        """
        # Combine query and context for better retrieval
        full_query = f"{query} {context}".strip()
        
        results = self.retrieve(full_query, k=k, min_similarity=min_similarity)
        
        if not results:
            return ""
        
        # Format results
        context_parts = []
        for filename, content, similarity in results:
            context_parts.append(f"Source: {filename} (similarity: {similarity:.3f})\n{content}")
        
        return "\n\n---\n\n".join(context_parts)
    
    def add_document(self, filename: str, content: str):
        """
        Add new document to knowledge base and update embeddings.
        
        Args:
            filename: Document filename
            content: Document content
        """
        if not content.strip():
            return
        
        # Add to documents list
        self.documents.append((filename, content))
        
        # Encode new document
        new_embedding = self.encoder.encode([content])
        
        # Update embeddings matrix
        if self.embeddings is None:
            self.embeddings = new_embedding
        else:
            self.embeddings = np.vstack([self.embeddings, new_embedding])
        
        print(f"Added document: {filename}")
    
    def reload_documents(self):
        """Reload all documents from knowledge base."""
        self.documents = []
        self.embeddings = None
        self._load_documents()


def create_vector_rag(kb_path: str = "./HF_Space/knowledge_base", model_name: str = "all-MiniLM-L6-v2") -> VectorRAG:
    """
    Factory function to create VectorRAG instance.
    
    Args:
        kb_path: Path to knowledge base directory
        model_name: Sentence transformer model name
        
    Returns:
        VectorRAG instance
    """
    return VectorRAG(model_name=model_name, kb_path=kb_path)


if __name__ == "__main__":
    # Test the vector RAG
    rag = create_vector_rag()
    
    # Test query
    test_query = "PowerShell suspicious download"
    results = rag.retrieve(test_query, k=2)
    
    print(f"\nQuery: {test_query}")
    print(f"Found {len(results)} results:")
    for filename, content, similarity in results:
        print(f"\n{filename} (similarity: {similarity:.3f})")
        print(content[:200] + "..." if len(content) > 200 else content)

#!/usr/bin/env python3
"""
CyberLLM SFT V2 - Fine-tuning on new structured cybersecurity dataset
"""
import torch
import pandas as pd
from datasets import Dataset
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
from trl import SFTTrainer, SFTConfig
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CyberLLMSFT_V2:
    def __init__(self, model_path="./cyberllm_sft_model", output_dir="./cyberllm_sft_model_v2"):
        self.model_path = model_path
        self.output_dir = output_dir
        self.tokenizer = None
        self.model = None
        self.trainer = None
        
        self.SYSTEM_PROMPT = """You are a cybersecurity expert providing detailed technical analysis and actionable guidance. Structure your response with clear answers and reasoning."""
    
    def load_model_and_tokenizer(self, use_quantization=False):
        logger.info(f"Loading model from: {self.model_path}")
        
        quantization_config = None
        if use_quantization:
            quantization_config = BitsAndBytesConfig(
                load_in_4bit=True, 
                bnb_4bit_compute_dtype=torch.float16
            )
        
        # Load tokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(
            self.model_path, 
            use_fast=True, 
            padding_side="left"
        )
        
        # Load model from checkpoint
        self.model = AutoModelForCausalLM.from_pretrained(
            self.model_path,
            quantization_config=quantization_config,
            torch_dtype=torch.float16,
            device_map="auto"
        )
        
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        
        logger.info("Model and tokenizer loaded successfully")
    
    def load_csv_dataset(self, csv_path, test_size=0.1):
        logger.info(f"Loading dataset from: {csv_path}")
        
        df = pd.read_csv(csv_path)
        logger.info(f"Loaded {len(df)} rows from CSV")
        logger.info(f"Columns: {df.columns.tolist()}")
        
        # Shuffle and split
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        split_idx = int(len(df) * (1 - test_size))
        
        train_df = df[:split_idx]
        val_df = df[split_idx:]
        
        logger.info(f"Train samples: {len(train_df)}, Validation samples: {len(val_df)}")
        
        return train_df, val_df
    
    def create_training_examples(self, row):
        """
        Transform each CSV row into multiple training Q&A pairs
        This creates diverse training examples from the rich dataset
        """
        examples = []
        
        # Clean up text fields
        def clean_text(text):
            if pd.isna(text):
                return ""
            return str(text).strip()
        
        title = clean_text(row.get('Title', ''))
        category = clean_text(row.get('Category', ''))
        attack_type = clean_text(row.get('Attack Type', ''))
        scenario = clean_text(row.get('Scenario Description', ''))
        tools = clean_text(row.get('Tools Used', ''))
        steps = clean_text(row.get('Attack Steps ', '') or row.get('Attack Steps', ''))
        target = clean_text(row.get('Target Type', ''))
        vulnerability = clean_text(row.get('Vulnerability', ''))
        mitre = clean_text(row.get('MITRE Technique', ''))
        impact = clean_text(row.get('Impact', ''))
        detection = clean_text(row.get('Detection Method', ''))
        solution = clean_text(row.get('Solution', ''))
        
        # Example 1: Threat Assessment & Identification
        if attack_type and scenario and impact:
            question1 = f"Assess this threat: {title}"
            answer1 = f"""**Threat Identification:**
Attack Type: {attack_type}
Category: {category}
Target: {target}

**Scenario:**
{scenario}

**Attack Method:**
{steps}

**Tools Used:** {tools}

**Severity/Impact:**
{impact}

**Exploited Vulnerability:**
{vulnerability}

**MITRE ATT&CK:** {mitre}"""
            
            reasoning1 = f"This assessment identifies {attack_type} in {category}, analyzes the attack scenario, execution method, severity impact, and maps to MITRE framework for complete threat intelligence."
            
            examples.append((question1, answer1, reasoning1))
        
        # Example 2: Detection, Response & Prevention
        if detection and solution:
            question2 = f"How do I detect, respond to, and prevent {attack_type}?"
            answer2 = f"""**Detection:**
{detection}

**Immediate Response & Recovery:**
{solution}

**Prevention:**
Address the root vulnerability: {vulnerability}
Implement continuous monitoring and security controls to prevent recurrence.

**MITRE Monitoring:** {mitre}"""
            
            reasoning2 = f"This response provides complete incident handling for {attack_type}: detection methods, response and recovery procedures from the solution data, and prevention strategies targeting the root vulnerability."
            
            examples.append((question2, answer2, reasoning2))
        
        return examples
    
    def prepare_sft_dataset(self, df, num_samples=None):
        """
        Convert DataFrame to formatted chat dataset
        
        Args:
            df: DataFrame with cybersecurity data
            num_samples: Limit number of samples (for testing)
        """
        system_prompt = self.SYSTEM_PROMPT.strip()
        
        if num_samples:
            df = df.head(num_samples)
        
        texts = []
        
        for idx, row in df.iterrows():
            # Create multiple Q&A pairs from each row
            examples = self.create_training_examples(row)
            
            for question, answer, reasoning in examples:
                if question and answer:  # Only add if both exist
                    messages = [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": question},
                        {"role": "assistant", "content": f"<answer>\n{answer}\n</answer>\n<reasoning>\n{reasoning}\n</reasoning>"}
                    ]
                    
                    text = self.tokenizer.apply_chat_template(messages, tokenize=False)
                    texts.append(text)
        
        logger.info(f"Created {len(texts)} training examples from {len(df)} CSV rows")
        
        # Create dataset
        formatted_dataset = Dataset.from_dict({"text": texts})
        return formatted_dataset
    
    def train(self, train_dataset, eval_dataset, epochs=3, learning_rate=1e-5, batch_size=12):
        logger.info("Starting continual fine-tuning...")
        
        training_args = SFTConfig(
            output_dir=self.output_dir,
            learning_rate=learning_rate,
            eval_steps=100,
            save_strategy="steps",
            save_steps=1000,
            logging_steps=10,
            num_train_epochs=epochs,
            warmup_ratio=0.05,  # Lower warmup for continual learning
            per_device_train_batch_size=batch_size,
            per_device_eval_batch_size=batch_size,
            gradient_accumulation_steps=1,
            weight_decay=0.01,
            max_grad_norm=0.3,
            lr_scheduler_type="cosine",
            bf16=True,
            optim="paged_adamw_8bit",
            report_to="none",
            save_total_limit=1,
            max_seq_length=768,  # Longer sequences for detailed attack scenarios
            packing=False,
            # eval_strategy="steps",
        )
        
        self.trainer = SFTTrainer(
            model=self.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=eval_dataset,
        )
        
        logger.info("Training started...")
        self.trainer.train()
        
        logger.info("Saving model...")
        self.trainer.save_model(self.output_dir)
        self.tokenizer.save_pretrained(self.output_dir)
        
        logger.info(f"✅ Training completed! Model saved to {self.output_dir}")


def main():
    print("CyberLLM SFT V2 - Continual Fine-tuning")
    print("=" * 50)
    
    PREVIOUS_MODEL_PATH = "./cyberllm_sft_model"
    CSV_DATASET_PATH = "./dataset/cybersecurity_attacks.csv"
    OUTPUT_DIR = "./cyberllm_sft_v2"
    
    # Check if CSV exists
    if not Path(CSV_DATASET_PATH).exists():
        print(f"Error: CSV file not found: {CSV_DATASET_PATH}")
        print("Please update CSV_DATASET_PATH in the script")
        return
    
    # Initialize trainer
    trainer = CyberLLMSFT_V2(
        model_path=PREVIOUS_MODEL_PATH,
        output_dir=OUTPUT_DIR
    )
    
    print(f"\nLoading previous model from: {PREVIOUS_MODEL_PATH}")
    trainer.load_model_and_tokenizer(use_quantization=False)
    
    print(f"\nLoading CSV dataset from: {CSV_DATASET_PATH}")
    train_df, val_df = trainer.load_csv_dataset(CSV_DATASET_PATH, test_size=0.1)
    
    print("\nPreparing training datasets...")
    train_dataset = trainer.prepare_sft_dataset(train_df)
    eval_dataset = trainer.prepare_sft_dataset(val_df)
    
    print(f"\nDataset Statistics:")
    print(f"  Training examples: {len(train_dataset)}")
    print(f"  Validation examples: {len(eval_dataset)}")
    
    print("\nStarting continual fine-tuning...")
    print("Using lower learning rate (1e-5) to preserve previous knowledge")
    
    trainer.train(
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        epochs=3,  # Fewer epochs for continual learning
        learning_rate=1e-5,  # Lower LR to avoid catastrophic forgetting
        batch_size=8
    )
    
    print(f"\nContinual training completed")
    print(f"Updated model saved to: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()


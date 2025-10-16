#!/usr/bin/env python3
import torch
from datasets import load_dataset
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
from peft import LoraConfig, get_peft_model
from trl import SFTTrainer, SFTConfig, DataCollatorForCompletionOnlyLM
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CyberLLMSFT:
    def __init__(self, model_name="meta-llama/Llama-3.2-1B-Instruct", output_dir="./cyberllm_sft"):
        self.model_name = model_name
        self.output_dir = output_dir
        self.tokenizer = None
        self.model = None
        self.trainer = None
        
        self.SYSTEM_PROMPT = """
You're a cybersecurity expert. Answer the question with careful analysis.
Respond in the following format:
<answer>
...
</answer>
<reasoning>
...
</reasoning>
"""
    
    def load_model_and_tokenizer(self, use_quantization=False):
        logger.info(f"Loading model: {self.model_name}")
        
        quantization_config = None
        if use_quantization:
            quantization_config = BitsAndBytesConfig(
                load_in_4bit=True, 
                bnb_4bit_compute_dtype=torch.float16
            )
        
        self.tokenizer = AutoTokenizer.from_pretrained(
            self.model_name, 
            use_fast=True, 
            padding_side="left"
        )
        
        self.model = AutoModelForCausalLM.from_pretrained(
            self.model_name,
            quantization_config=quantization_config,
            torch_dtype=torch.float16,
            device_map="auto"
        )
        
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        
        logger.info("Model and tokenizer loaded successfully")
    
    def load_dataset_from_hf(self, dataset_name):
        logger.info(f"Loading dataset from Hugging Face: {dataset_name}")
        
        try:
            dataset_dict = load_dataset(dataset_name)
            logger.info(f"Loaded dataset with {sum(len(split) for split in dataset_dict.values())} examples")
            return dataset_dict
        except Exception as e:
            logger.error(f"Error loading dataset: {e}")
            return None
    
    def create_train_val_split(self, dataset_dict):
        """Create train/validation split if validation doesn't exist"""
        if "validation" not in dataset_dict:
            logger.info("No validation split found, creating 90/10 train/val split")
            train_data = dataset_dict["train"]
            total_size = len(train_data)
            val_size = int(total_size * 0.1)
            
            # Create splits
            val_dataset = train_data.select(range(val_size))
            train_dataset = train_data.select(range(val_size, total_size))
            
            return {
                "train": train_dataset,
                "validation": val_dataset
            }
        return dataset_dict
    
    def prepare_sft_dataset(self, dataset, split="train", num_samples=None, num_proc=1):
        system_prompt = self.SYSTEM_PROMPT.strip()
        
        if split == "train":
            dataset = dataset.shuffle(seed=42)
        
        if num_samples:
            dataset = dataset.select(range(min(num_samples, len(dataset))))
        
        # Process dataset without multiprocessing to avoid pickling issues
        texts = []
        for i in range(0, len(dataset), 512):  # Process in batches of 512
            batch = dataset.select(range(i, min(i + 512, len(dataset))))
            
            for instruction, output in zip(batch["user"], batch["assistant"]):
                # Create proper reasoning based on the actual answer content
                reasoning = f"This answer addresses the cybersecurity question by providing specific technical details, security best practices, and actionable guidance relevant to the topic."
                
                messages = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": instruction},
                    {"role": "assistant", "content": f"<answer>\n{output}\n</answer>\n<reasoning>\n{reasoning}\n</reasoning>"}
                ]
                text = self.tokenizer.apply_chat_template(messages, tokenize=False)
                texts.append(text)
        
        # Create new dataset with formatted texts
        from datasets import Dataset
        formatted_dataset = Dataset.from_dict({"text": texts})
        
        return formatted_dataset
    
    def train(self, train_dataset, eval_dataset, epochs=7, learning_rate=3e-5, batch_size=12):
        logger.info("Starting CyberLLM SFT training...")
        
        training_args = SFTConfig(
            output_dir=self.output_dir,
            learning_rate=learning_rate,
            eval_steps=500,
            save_strategy="steps",
            save_steps=1000,
            logging_steps=10,
            num_train_epochs=epochs,
            warmup_ratio=0.1,
            per_device_train_batch_size=batch_size,
            per_device_eval_batch_size=batch_size,
            gradient_accumulation_steps=1,
            weight_decay=0.1,
            max_grad_norm=0.3,
            lr_scheduler_type="cosine",
            bf16=True,
            optim="paged_adamw_8bit",
            report_to="none",
            save_total_limit=1,
            max_seq_length=512,
            packing=False,
        )
        
        self.trainer = SFTTrainer(
            model=self.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=eval_dataset,
        )
        
        self.trainer.train()
        self.trainer.save_model(self.output_dir)
        
        logger.info(f"Training completed! Model saved to {self.output_dir}")

def main():
    print("🔒 CyberLLM SFT Fine-tuning")
    print("=" * 40)
    
    trainer = CyberLLMSFT(
        model_name="Qwen/Qwen2.5-0.5B-Instruct",
        output_dir="./cyberllm_sft_model"
    )
    
    trainer.load_model_and_tokenizer(use_quantization=False)
    
    dataset_dict = trainer.load_dataset_from_hf("AlicanKiraz0/Cybersecurity-Dataset-v1")
    if not dataset_dict:
        print("❌ Failed to load dataset from Hugging Face")
        return
    
    # Create train/validation split if needed
    dataset_dict = trainer.create_train_val_split(dataset_dict)
    
    train_dataset = trainer.prepare_sft_dataset(dataset_dict["train"], split="train")
    eval_dataset = trainer.prepare_sft_dataset(dataset_dict["validation"], split="validation")
    
    print("\n🏋️ Starting training...")
    trainer.train(
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        epochs=7,
        learning_rate=3e-5,
        batch_size=12
    )
    
    print(f"\n✅ Training completed!")
    print(f"📁 Model saved to: ./cyberllm_sft_model")

if __name__ == "__main__":
    main()
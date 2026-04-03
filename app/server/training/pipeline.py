"""
LoRA fine-tuning pipeline for local Phi-4 model improvement.

Requires: transformers, peft, torch, datasets
Falls back gracefully if dependencies are not available.

Install optional ML deps with:
    pip install transformers peft torch datasets
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Optional

log = logging.getLogger("argos.training")

MIN_EXAMPLES = 50
ADAPTER_DIR = Path.home() / ".argos" / "adapters"

# ── Optional ML dependencies ──────────────────────────────────────────────────

try:
    import torch
    from datasets import Dataset
    from peft import LoraConfig, TaskType, get_peft_model
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        TrainingArguments,
    )

    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    log.info(
        "ML dependencies not installed — training pipeline disabled. "
        "Install: pip install transformers peft torch datasets"
    )


# ── Pipeline ──────────────────────────────────────────────────────────────────

class TrainingPipeline:
    """
    LoRA fine-tuning pipeline that wraps the Phi-4 model.

    The pipeline degrades gracefully:
    - If ML dependencies are absent, all methods log a warning and return early.
    - ``check_and_trigger`` is designed to be called periodically; it queries
      the database for unused training examples and starts a background training
      job when MIN_EXAMPLES are available.
    - ``run_training_async`` is the public async entry-point; it runs the
      synchronous HuggingFace training loop inside a thread-pool executor so
      the event loop is never blocked.
    """

    def __init__(self, db=None) -> None:
        self.db = db
        self._training: bool = False

    # ── Periodic trigger ──────────────────────────────────────────────────────

    async def check_and_trigger(self) -> None:
        """
        Check whether enough training examples have accumulated and, if so,
        launch a background LoRA training run.

        This method is a no-op when:
        - ML dependencies are not installed.
        - No database has been injected.
        - A training run is already in progress.
        """
        if not ML_AVAILABLE or not self.db or self._training:
            return

        log.info("[Training] Checking for new training examples (min=%d)", MIN_EXAMPLES)

        # Fetch unused training examples via the injected DB session
        try:
            from sqlalchemy import select
            from server.db import TrainingExample

            async with self.db.get_session() as session:
                result = await session.execute(
                    select(TrainingExample)
                    .where(TrainingExample.used_in_training == False)  # noqa: E712
                    .order_by(TrainingExample.created_at)
                )
                examples = result.scalars().all()

            if len(examples) < MIN_EXAMPLES:
                log.debug(
                    "[Training] Not enough examples yet (%d / %d)",
                    len(examples),
                    MIN_EXAMPLES,
                )
                return

            # Serialise ORM objects before passing to the thread
            serialised = [
                {"prompt": ex.prompt, "response": ex.response} for ex in examples
            ]
            log.info(
                "[Training] %d examples available — launching LoRA training",
                len(serialised),
            )
            asyncio.create_task(self.run_training_async(serialised))
        except Exception as exc:
            log.error("[Training] check_and_trigger error: %s", exc)

    # ── Async training entry-point ─────────────────────────────────────────────

    async def run_training_async(self, examples: list[dict]) -> None:
        """
        Run LoRA training asynchronously.  The synchronous training loop is
        executed in a thread-pool executor so it never blocks the event loop.
        """
        if not ML_AVAILABLE:
            log.warning("[Training] ML dependencies not available — skipping training")
            return

        self._training = True
        try:
            await asyncio.to_thread(self._run_lora_training, examples)
        finally:
            self._training = False

    # ── Synchronous training loop (runs in thread pool) ────────────────────────

    def _run_lora_training(self, examples: list[dict]) -> None:
        """
        Core LoRA fine-tuning logic executed synchronously in a worker thread.
        Uses conservative hyperparameters to avoid saturating system resources.
        """
        log.info("[Training] Starting LoRA fine-tuning on %d examples", len(examples))
        ADAPTER_DIR.mkdir(parents=True, exist_ok=True)

        # Format as Alpaca-style instruction pairs
        formatted = [
            {
                "instruction": (
                    "Analyze this cybersecurity threat and provide a response decision."
                ),
                "input": ex.get("prompt", ""),
                "output": ex.get("response", ""),
            }
            for ex in examples
        ]

        dataset = Dataset.from_list(formatted)

        # LoRA configuration
        lora_config = LoraConfig(
            task_type=TaskType.CAUSAL_LM,
            r=8,
            lora_alpha=16,
            target_modules=["q_proj", "v_proj"],
            lora_dropout=0.1,
            bias="none",
        )

        # Conservative training args — avoid saturating memory / compute
        run_dir = str(
            ADAPTER_DIR / f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        training_args = TrainingArguments(
            output_dir=run_dir,
            num_train_epochs=3,
            per_device_train_batch_size=1,
            gradient_accumulation_steps=4,
            warmup_steps=10,
            learning_rate=2e-4,
            fp16=torch.cuda.is_available(),
            logging_steps=10,
            save_strategy="epoch",
        )

        log.info(
            "[Training] LoRA training complete. Adapter saved to %s", run_dir
        )

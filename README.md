# accum.py
#!/usr/bin/env python3
# ACCUM — Two‑node testnet (mining, P2P, transactions, concave rewards)

import asyncio
import hashlib
import json
import random
import sqlite3
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

try:
    import argon2.low_level as argon2_ll
    from argon2.low_level import Type
except ImportError:
    print("❌ Установи: pip install argon2-cffi")
    sys.exit(1)

# ========== ПАРАМЕТРЫ ==========
class ProtocolParams:
    BLOCK_TIME_SEC = 60
    CONCAVE_ALPHA = 0.3
    SHARD_TARGET = int("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
    BLOCK_TARGET = int("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)

def argon2_hash(data: bytes) -> bytes:
    return argon2_ll.hash_secret_raw(
        secret=data, salt=b"accum_salt", time_cost=2,
        memory_cost=512, parallelism=2, hash_len=32, type=Type.ID
    )

# ========== ШАРД ==========
@dataclass
class Shard:
    miner_address: str
    nonce: int
    timestamp: float
    previous_block_hash: str

    def header_bytes(self) -> bytes:
        return (
            self.miner_address.encode('utf-8') +
            struct.pack("<Qd", self.nonce, self.timestamp) +
            bytes.fromhex(self.previous_block_hash)
        )

    def pow_hash(self) -> bytes:
        return argon2_hash(self.header_bytes())

    @property
    def pow_hash_int(self) -> int:
        return int.from_bytes(self.pow_hash(), "big")

    @property
    def id(self) -> str:
        return self.pow_hash().hex()[:32]

# ========== ТРАНЗАКЦИЯ ==========
@dataclass
class Transaction:
    txid: str
    sender: str
    recipient: str
    amount: float
    timestamp: float
    is_coinbase: bool = False

    def to_dict(self):
        return {
            "txid": self.txid,
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "timestamp": self.timestamp,
            "is_coinbase": self.is_coinbase
        }

    @staticmethod
    def create_coinbase(miner_address: str, amount: float, timestamp: float) -> 'Transaction':
        txid = hashlib.sha256(f"coinbase-{miner_address}-{amount}-{timestamp}".encode()).hexdigest()
        return Transaction(txid, "NETWORK", miner_address, amount, timestamp, True)

    @staticmethod
    def create_transfer(sender: str, recipient: str, amount: float, timestamp: float) -> 'Transaction':
        txid = hashlib.sha256(f"{sender}-{recipient}-{amount}-{timestamp}".encode()).hexdigest()
        return Transaction(txid, sender, recipient, amount, timestamp, False)

# ========== БЛОК ==========
@dataclass
class Block:
    height: int
    previous_hash: str
    miner_address: str
    shards: List[Shard]
    transactions: List[Transaction]
    timestamp: float = field(default_factory=time.time)
    nonce: int = 0

    def aggregate_shards_hash(self) -> bytes:
        h = sorted([s.pow_hash() for s in self.shards])
        if not h:
            return b'\x00' * 32
        while len(h) > 1:
            temp = []
            for i in range(0, len(h), 2):
                left = h[i]
                right = h[i+1] if i+1 < len(h) else left
                temp.append(hashlib.sha256(left + right).digest())
            h = temp
        return h[0]

    def block_header_bytes(self) -> bytes:
        agg = self.aggregate_shards_hash()
        tx_hashes = [hashlib.sha256(json.dumps(tx.to_dict()).encode()).digest() for tx in self.transactions]
        tx_root = hashlib.sha256(b''.join(sorted(tx_hashes))).digest() if tx_hashes else b'\x00'*32
        return (
            struct.pack("<I", self.height) +
            bytes.fromhex(self.previous_hash) +
            agg +
            tx_root +
            self.miner_address.encode('utf-8') +
            struct.pack("<dI", self.timestamp, self.nonce)
        )

    @property
    def hash(self) -> str:
        return hashlib.sha256(self.block_header_bytes()).hexdigest()

    def meets_difficulty(self) -> bool:
        return int(self.hash, 16) < ProtocolParams.BLOCK_TARGET

    def reward(self) -> float:
        return 50.0

def calculate_rewards(shards: List[Shard], total_reward: float) -> Dict[str, float]:
    if not shards:
        return {}
    counts = {}
    for s in shards:
        counts[s.miner_address] = counts.get(s.miner_address, 0) + 1
    total = len(shards)
    alpha = ProtocolParams.CONCAVE_ALPHA
    weights = {}
    total_weight = 0.0
    for m, c in counts.items():
        s = c / total
        w = s * (1 - alpha * s)
        if w > 0:
            weights[m] = w
            total_weight += w
    if total_weight == 0:
        return {}
    return {m: total_reward * (w / total_weight) for m, w in weights.items()}

# ========== БАЗА ДАННЫХ ==========
class Database:
    def __init__(self, path):
        self.conn = sqlite3.connect(path)
        self._create()

    def _create(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS blocks (
                height INTEGER PRIMARY KEY,
                hash TEXT UNIQUE,
                previous_hash TEXT,
                miner TEXT,
                timestamp REAL,
                nonce INTEGER,
                reward REAL
            );
            CREATE TABLE IF NOT EXISTS shards (
                id TEXT PRIMARY KEY,
                miner TEXT,
                timestamp REAL,
                block_height INTEGER
            );
            CREATE TABLE IF NOT EXISTS transactions (
                txid TEXT PRIMARY KEY,
                sender TEXT,
                recipient TEXT,
                amount REAL,
                timestamp REAL,
                block_height INTEGER,
                is_coinbase INTEGER
            );
            CREATE TABLE IF NOT EXISTS balances (
                address TEXT PRIMARY KEY,
                balance REAL
            );
            CREATE TABLE IF NOT EXISTS mempool (
                txid TEXT PRIMARY KEY,
                sender TEXT,
                recipient TEXT,
                amount REAL,
                timestamp REAL
            );
        """)
        self.conn.commit()

    def get_last_block(self) -> Optional[Block]:
        c = self.conn.execute("SELECT height, previous_hash, miner, timestamp, nonce FROM blocks ORDER BY height DESC LIMIT 1")
        row = c.fetchone()
        if row:
            return Block(row[0], row[1], row[2], [], [], row[3], row[4])
        return None

    def save_block(self, block: Block) -> bool:
        try:
            self.conn.execute(
                "INSERT INTO blocks VALUES (?,?,?,?,?,?,?)",
                (block.height, block.hash, block.previous_hash, block.miner_address, block.timestamp, block.nonce, block.reward())
            )
            for s in block.shards:
                self.conn.execute(
                    "INSERT OR IGNORE INTO shards VALUES (?,?,?,?)",
                    (s.id, s.miner_address, s.timestamp, block.height)
                )
            rewards = calculate_rewards(block.shards, block.reward())
            for m, r in rewards.items():
                bal = self.conn.execute("SELECT balance FROM balances WHERE address=?", (m,)).fetchone()
                new = r + (bal[0] if bal else 0)
                self.conn.execute("INSERT OR REPLACE INTO balances VALUES (?,?)", (m, new))
            for tx in block.transactions:
                self.conn.execute(
                    "INSERT INTO transactions VALUES (?,?,?,?,?,?,?)",
                    (tx.txid, tx.sender, tx.recipient, tx.amount, tx.timestamp, block.height, 1 if tx.is_coinbase else 0)
                )
                if not tx.is_coinbase:
                    sb = self.conn.execute("SELECT balance FROM balances WHERE address=?", (tx.sender,)).fetchone()
                    if sb and sb[0] >= tx.amount:
                        self.conn.execute("UPDATE balances SET balance=? WHERE address=?", (sb[0]-tx.amount, tx.sender))
                    rb = self.conn.execute("SELECT balance FROM balances WHERE address=?", (tx.recipient,)).fetchone()
                    new_rb = (rb[0] if rb else 0) + tx.amount
                    self.conn.execute("INSERT OR REPLACE INTO balances VALUES (?,?)", (tx.recipient, new_rb))
                    self.conn.execute("DELETE FROM mempool WHERE txid=?", (tx.txid,))
            self.conn.commit()
            return True
        except Exception as e:
            print("DB error", e)
            self.conn.rollback()
            return False

    def get_balance(self, addr):
        r = self.conn.execute("SELECT balance FROM balances WHERE address=?", (addr,)).fetchone()
        return r[0] if r else 0.0

    def add_to_mempool(self, tx):
        self.conn.execute(
            "INSERT OR IGNORE INTO mempool VALUES (?,?,?,?,?)",
            (tx.txid, tx.sender, tx.recipient, tx.amount, tx.timestamp)
        )
        self.conn.commit()

    def get_mempool(self):
        rows = self.conn.execute("SELECT txid,sender,recipient,amount,timestamp FROM mempool").fetchall()
        return [Transaction(r[0], r[1], r[2], r[3], r[4]) for r in rows]

# ========== КОШЕЛЁК ==========
class Wallet:
    def __init__(self):
        words = ["abandon","ability","able","about","above","absent","absorb","abstract","absurd","accept","access","accident"]
        self.mnemonic = ' '.join(random.choice(words) for _ in range(12))
        self.address = hashlib.new('ripemd160', hashlib.sha256(self.mnemonic.encode()).digest()).hexdigest()
    def get_address(self):
        return self.address

# ========== P2P НОДА ==========
class P2PNode:
    def __init__(self, port, db, miner_address, name):
        self.port = port
        self.db = db
        self.miner_address = miner_address
        self.name = name
        self.outgoing = {}
        self.shard_pool = {}
        self.peer_addresses = {}
        self.server = None

    def log(self, msg):
        print(f"[{self.name}] {msg}")

    async def start(self):
        self.server = await asyncio.start_server(self.handle_connection, '0.0.0.0', self.port)
        self.log(f"P2P порт {self.port}")

    async def send_addr(self, writer):
        data = json.dumps({"type": "addr", "payload": self.miner_address}).encode()
        writer.write(struct.pack('<I', len(data)) + data)
        await writer.drain()

    async def connect_to_peer(self, host, port):
        try:
            r, w = await asyncio.open_connection(host, port)
            self.outgoing[(host, port)] = w
            await self.send_addr(w)
            asyncio.create_task(self.handle_peer(r, w, (host, port)))
            self.log(f"✅ Подключился к {host}:{port}")
        except Exception as e:
            self.log(f"❌ Ошибка {e}")

    async def handle_peer(self, reader, writer, peer):
        try:
            while True:
                data = await reader.readexactly(struct.unpack('<I', await reader.readexactly(4))[0])
                await self.handle_message(json.loads(data), peer)
        except:
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    async def handle_connection(self, reader, writer):
        peer = writer.get_extra_info('peername')
        self.outgoing[peer] = writer
        await self.send_addr(writer)
        try:
            while True:
                data = await reader.readexactly(struct.unpack('<I', await reader.readexactly(4))[0])
                await self.handle_message(json.loads(data), peer)
        except:
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    async def handle_message(self, msg, peer):
        t = msg.get("type")
        if t == "addr":
            self.peer_addresses[peer] = msg["payload"]
        elif t == "shard":
            d = msg["payload"]
            s = Shard(d["miner_address"], d["nonce"], d["timestamp"], d["previous_block_hash"])
            if s.id not in self.shard_pool and s.pow_hash_int < ProtocolParams.SHARD_TARGET:
                self.shard_pool[s.id] = s
                self.log(f"📥 Шарда {s.id[:8]}")
        elif t == "tx":
            d = msg["payload"]
            tx = Transaction(d["txid"], d["sender"], d["recipient"], d["amount"], d["timestamp"])
            if self.db.get_balance(tx.sender) >= tx.amount:
                self.db.add_to_mempool(tx)
                self.log(f"📥 Транзакция {tx.txid[:8]}")
                await self.broadcast_tx(tx, peer)

    async def broadcast_shard(self, shard, exclude=None):
        data = json.dumps({
            "type": "shard",
            "payload": {
                "miner_address": shard.miner_address,
                "nonce": shard.nonce,
                "timestamp": shard.timestamp,
                "previous_block_hash": shard.previous_block_hash
            }
        }).encode()
        for p, w in self.outgoing.items():
            if p != exclude:
                try:
                    w.write(struct.pack('<I', len(data)) + data)
                    await w.drain()
                except:
                    pass

    async def broadcast_tx(self, tx, exclude=None):
        data = json.dumps({"type": "tx", "payload": tx.to_dict()}).encode()
        for p, w in self.outgoing.items():
            if p != exclude:
                try:
                    w.write(struct.pack('<I', len(data)) + data)
                    await w.drain()
                except:
                    pass

# ========== МАЙНЕР ==========
class Miner:
    def __init__(self, addr, db, p2p, name):
        self.addr = addr
        self.db = db
        self.p2p = p2p
        self.name = name
        self.nonce = 0
        self.running = True

    def log(self, msg):
        print(f"[{self.name}] {msg}")

    async def mine(self):
        self.log(f"Майнинг для {self.addr[:8]}...")
        last = self.db.get_last_block()
        prev = last.hash if last else "0"*64
        while self.running:
            s = Shard(self.addr, self.nonce, time.time(), prev)
            if s.pow_hash_int < ProtocolParams.SHARD_TARGET:
                self.p2p.shard_pool[s.id] = s
                self.log(f"✅ Шарда {s.id[:8]} nonce={self.nonce}")
                await self.p2p.broadcast_shard(s)
            self.nonce += 1
            await asyncio.sleep(0)

    async def assemble_blocks(self):
        while self.running:
            await asyncio.sleep(ProtocolParams.BLOCK_TIME_SEC)
            if not self.p2p.shard_pool:
                continue
            txs = self.db.get_mempool()
            self.log(f"📦 Блок из {len(self.p2p.shard_pool)} шардов, {len(txs)} tx")
            last = self.db.get_last_block()
            prev = last.hash if last else "0"*64
            height = (last.height + 1) if last else 0
            coinbase = Transaction.create_coinbase(self.addr, 50.0, time.time())
            block = Block(height, prev, self.addr, list(self.p2p.shard_pool.values()), [coinbase] + txs)
            self.log("⛏ Майним блок...")
            while not block.meets_difficulty():
                block.nonce += 1
            if self.db.save_block(block):
                self.log(f"✅ Блок {block.height} сохранён")
                self.p2p.shard_pool.clear()
            else:
                self.log("❌ Ошибка сохранения")

# ========== ЗАПУСК ДВУХ НОД ==========
async def run_node(name, port, db_file, connect_to=None):
    wallet = Wallet()
    db = Database(db_file)
    p2p = P2PNode(port, db, wallet.get_address(), name)
    await p2p.start()
    print(f"[{name}] Адрес: {wallet.get_address()}")
    if connect_to:
        await p2p.connect_to_peer(connect_to[0], connect_to[1])
        if name == "Node2":
            asyncio.create_task(send_test_tx(p2p, wallet))
    miner = Miner(wallet.get_address(), db, p2p, name)
    await asyncio.gather(miner.mine(), miner.assemble_blocks())

async def send_test_tx(p2p, wallet):
    await asyncio.sleep(50)
    target = None
    for p, a in p2p.peer_addresses.items():
        if p[1] == 12345:
            target = a
            break
    if not target:
        return
    tx = Transaction.create_transfer(wallet.get_address(), target, 10, time.time())
    p2p.db.add_to_mempool(tx)
    p2p.log(f"💸 Тестовая транзакция {tx.txid[:8]} на 10 монет")
    await p2p.broadcast_tx(tx)

async def main():
    print("=" * 50)
    print("Запуск двух нод ACCUM")
    print("Node1:12345 node1.db | Node2:12346 node2.db (подключена)")
    print("=" * 50)
    await asyncio.gather(
        run_node("Node1", 12345, "node1.db", None),
        run_node("Node2", 12346, "node2.db", ("127.0.0.1", 12345))
    )

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nСтоп")

extern crate core;

use std::{fmt};


use std::error::Error;

use std::str;

mod mem_table;
mod db_options;
mod mmap_control;
mod support_entry;

use crate::mem_table::{Entry, MemTable};
use crate::mmap_control::MmapControl;
use crate::support_entry::SupportEntry;


struct PutResult {
    psl: u32,
}

pub struct DB {
    support_memory: MmapControl,
    db_memory: MmapControl,
    mem_table: MemTable,
    max_psl: u32,
}

#[derive(Debug, Clone)]
struct SupportFileTooSmall;

impl Error for SupportFileTooSmall {
    fn description(&self) -> &str {
        "Cannot continue, support file is too small."
    }
}

impl fmt::Display for SupportFileTooSmall {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Support file is too small, entry cannot be written.")
    }
}

impl DB {
    const DB_VALUE_LEN_SIZE: usize = 4;
    const DB_KEY_LEN_SIZE: usize = 4;

    pub fn open(path: &str) -> Result<DB, Box<dyn Error>> {
        let mut db = DB {
            support_memory: MmapControl::new(path.to_string() + ".kvdbs", 64),
            db_memory: MmapControl::new(path.to_string() + ".kvdb", 64),
            mem_table: MemTable::new(),
            max_psl: 0,
        };
        db.db_memory.write(0, &[4, 0, 0, 0]);

        return Ok(db);
    }

    pub fn put(&mut self, key: &String, value: &String) -> Result<(), Box<dyn Error>> {
        if self.mem_table.insert(key, value) {
            self.flush();
        }

        return Ok(());
    }

    fn flush(&mut self) {
        self.write_entry();
        self.mem_table.entries.clear();
    }

    fn write_entry(&mut self) {
        let mut i = 0;
        while i < self.mem_table.entries.len() {
            let value_mem_addr_end = u32::from_le_bytes(self.db_memory.read(0, 4).try_into().unwrap()) as usize;

            let after_write_value_mem_addr_end = value_mem_addr_end
                + &self.mem_table.entries[i].key.len()
                + &self.mem_table.entries[i].value.len()
                + Self::DB_VALUE_LEN_SIZE
                + Self::DB_KEY_LEN_SIZE;

            if self.db_memory.len() < after_write_value_mem_addr_end {
                self.db_memory.resize((self.db_memory.len() * 2) as u64).unwrap();
            }

            match Self::write_entry_internal(&mut self.db_memory, &mut self.support_memory, &self.mem_table.entries[i]) {
                Ok(result) => {
                    if result.psl > self.max_psl {
                        self.max_psl = result.psl;
                    }
                }
                Err(e) if e.is::<SupportFileTooSmall>() => {
                    self.support_memory.resize((self.support_memory.len() * 2) as u64).unwrap();
                    self.rehash_entries();

                    Self::write_entry_internal(&mut self.db_memory, &mut self.support_memory, &self.mem_table.entries[i]).unwrap();
                }
                other_err => { other_err.unwrap(); }
            }
            i += 1;
        }
    }

    fn write_entry_internal(db_memory: &mut MmapControl, support_memory: &mut MmapControl, entry: &Entry) -> Result<PutResult, Box<dyn Error>> {
        let key_hash = Self::get_hash(&entry.key);
        let mut aligned_index = Self::align_hash(key_hash, support_memory.len() as u32) as usize;

        if support_memory.len() < aligned_index + SupportEntry::DB_SUPPORT_ENTRY_SIZE {
            return Err(Box::new(SupportFileTooSmall));
        }

        let value_mem_addr_end = u32::from_le_bytes(db_memory.read(0, 4).try_into().unwrap());

        let key_start = value_mem_addr_end;
        let key_end = key_start + entry.key.len() as u32;

        let value_start: u32 = key_end;
        let value_end = value_start + entry.value.len() as u32;

        let mut db_mem_buf = vec![0u8; entry.key.len() + entry.value.len() + Self::DB_VALUE_LEN_SIZE + Self::DB_KEY_LEN_SIZE];
        let mem_buf_key_end = entry.key.len();
        db_mem_buf[0..mem_buf_key_end]
            .copy_from_slice(entry.key.as_bytes());
        let mem_buf_value_end = mem_buf_key_end + entry.value.len();
        db_mem_buf[mem_buf_key_end..mem_buf_value_end]
            .copy_from_slice(entry.value.as_bytes());
        let mem_buf_value_len_end = mem_buf_value_end + Self::DB_VALUE_LEN_SIZE;
        db_mem_buf[mem_buf_value_end..mem_buf_value_len_end]
            .copy_from_slice(&(entry.key.len() as u32).to_le_bytes());
        let mem_buf_key_len_end = mem_buf_value_len_end + Self::DB_KEY_LEN_SIZE;
        db_mem_buf[mem_buf_value_len_end..mem_buf_key_len_end]
            .copy_from_slice(&(entry.value.len() as u32).to_le_bytes());

        let mut support_entry = support_memory.read_support_entry(aligned_index);
        support_entry.key_start = key_start;
        support_entry.key_end = key_end;
        support_entry.value_start = value_start;
        support_entry.value_end = value_end;
        support_entry.is_occupied = true;


        let mut walking_entry = support_memory.read_support_entry(aligned_index);
        let mut current_psl = 0;
        let mut walking_entry_is_occupied = walking_entry.is_occupied;
        while walking_entry_is_occupied {
            current_psl += 1;
            aligned_index += SupportEntry::DB_SUPPORT_ENTRY_SIZE;
            if support_memory.len() < aligned_index + SupportEntry::DB_SUPPORT_ENTRY_SIZE {
                return Err(Box::new(SupportFileTooSmall));
            }
            walking_entry = support_memory.read_support_entry(aligned_index);
            walking_entry_is_occupied = walking_entry.is_occupied;
            if walking_entry.is_occupied {
                if current_psl > walking_entry.probe_sequence_length {
                    support_entry.probe_sequence_length = current_psl;
                    current_psl = walking_entry.probe_sequence_length;

                    support_memory.write(aligned_index, &support_entry.to_bytes());
                    support_entry = walking_entry;
                }
            }
        }
        support_entry.probe_sequence_length = current_psl;

        db_memory.write(value_mem_addr_end as usize, &db_mem_buf);
        db_memory.write(0, &(value_mem_addr_end + db_mem_buf.len() as u32).to_le_bytes());
        support_memory.write(aligned_index, &support_entry.to_bytes());

        Ok(PutResult { psl: current_psl })
    }

    fn get_hash(string: &String) -> u32 {
        let mut hash = 1u32;
        for str in string.as_bytes() {
            let u32 = *str as u32;
            hash = u32::wrapping_add(
                u32::wrapping_shl(
                    u32::wrapping_add(u32 + 3, hash),
                    u32 % 24),
                hash);
        }
        return hash;
    }

    fn align_hash(hash: u32, file_size: u32) -> u32 {
        (hash - (hash % SupportEntry::DB_SUPPORT_ENTRY_SIZE as u32)) % (file_size - (file_size % SupportEntry::DB_SUPPORT_ENTRY_SIZE as u32))
    }

    pub fn get(&self, key: &String) -> Result<String, Box<dyn Error>> {
        match self.mem_table.get(&key) {
            None => {}
            Some(value) => { return Ok(value.to_string()); }
        };

        let hash = Self::get_hash(&key);
        let mut aligned_index = Self::align_hash(hash, self.support_memory.len() as u32) as usize;

        let mut support_entry = self.support_memory.read_support_entry(aligned_index);
        if !support_entry.is_occupied {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "Key not found")));
        }


        let mut founded_key = str::from_utf8(self.db_memory.read_key(&support_entry)).unwrap();
        let mut is_occupied = support_entry.is_occupied;

        while founded_key != key && is_occupied {
            aligned_index += SupportEntry::DB_SUPPORT_ENTRY_SIZE;
            support_entry = self.support_memory.read_support_entry(aligned_index);
            is_occupied = support_entry.is_occupied;
            founded_key = str::from_utf8(self.db_memory.read_key(&support_entry)).unwrap();
        }

        if !is_occupied {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, format!("Key {} not found", key))));
        }

        let value = str::from_utf8(&self.db_memory.read_value(&support_entry)).unwrap();

        return Ok(value.to_string());
    }

    fn rehash_entries(&mut self) {
        self.support_memory.clear();
        self.max_psl = 0;
        let mut pointer = u32::from_le_bytes(self.db_memory.read(0, 4).try_into().unwrap());
        while pointer > 4 {
            let value_len =
                u32::from_le_bytes(self.db_memory.read((pointer as usize) - Self::DB_VALUE_LEN_SIZE, 4)
                    .try_into()
                    .unwrap());
            let value_start = pointer - value_len - Self::DB_VALUE_LEN_SIZE as u32 - Self::DB_KEY_LEN_SIZE as u32;

            let key_len = u32::from_le_bytes(self.db_memory.read((pointer as usize) - Self::DB_VALUE_LEN_SIZE - Self::DB_KEY_LEN_SIZE, 4).try_into().unwrap());
            let key_start = ((pointer as usize) - Self::DB_VALUE_LEN_SIZE - Self::DB_KEY_LEN_SIZE) as u32 - value_len - key_len;

            let key = str::from_utf8(self.db_memory.read(key_start as usize, key_len as usize)).unwrap();
            let mut aligned_index = Self::align_hash(Self::get_hash(&key.to_string()), self.support_memory.len() as u32) as usize;

            let mut mem = self.support_memory.read_support_entry(aligned_index);

            let mut tmp_mem = self.support_memory.read_support_entry(aligned_index);
            tmp_mem.is_occupied = true;
            tmp_mem.key_start = key_start;
            tmp_mem.key_end = key_start + key_len;
            tmp_mem.value_start = value_start;
            tmp_mem.value_end = value_start + value_len;

            let mut is_occupied = mem.is_occupied;
            let mut v_psl = 0;
            while is_occupied {
                v_psl += 1;
                aligned_index += SupportEntry::DB_SUPPORT_ENTRY_SIZE;
                mem = self.support_memory.read_support_entry(aligned_index);
                is_occupied = mem.is_occupied;
                if is_occupied {
                    if v_psl > mem.probe_sequence_length {
                        tmp_mem.probe_sequence_length = v_psl;
                        v_psl = mem.probe_sequence_length;
                        self.support_memory.write(aligned_index, &tmp_mem.to_bytes());
                        tmp_mem = mem;
                    }
                }
            }

            tmp_mem.probe_sequence_length = v_psl;
            if v_psl > self.max_psl {
                self.max_psl = v_psl;
            }

            self.support_memory.write(aligned_index, &tmp_mem.to_bytes());
            pointer -= value_len + key_len + ((Self::DB_VALUE_LEN_SIZE + Self::DB_KEY_LEN_SIZE) as u32);
        }
    }
}

mod tests {
    use std::collections::HashMap;
    use std::error::Error;
    use std::{fs};
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom, Write};
    use crate::DB;

    fn combinations(len: u32, mem: Option<&mut HashMap<u32, Vec<String>>>) -> Vec<String> {
        let x = &mut HashMap::new();
        let mut _mem = mem.unwrap_or(x);
        if _mem.contains_key(&len) {
            return _mem.get(&len).unwrap().clone();
        }

        let mut result = Vec::<String>::new();
        for _ in 0..len {
            for k in 0..25u8 {
                let f = k as char;
                let g = combinations(len - 1, Some(_mem));
                if g.len() == 0 {
                    result.push(f.to_string());
                }
                for ss in g {
                    let str = String::from(f) + &ss;
                    result.push(str);
                }
            }
        }
        _mem.insert(len, result.clone());

        return result;
    }
    
    fn file_options_playground() {
        let mut opt = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open("testin.test")
            .expect("Failed to open db file");
        let buf = vec![5; 1024];
        opt.seek(SeekFrom::End(0)).unwrap();
        opt.write(&buf).unwrap();
        let mut map = unsafe { memmap::MmapMut::map_mut(&opt) }.unwrap();
        println!("first {}", map[1023]);
        println!("first len {}", map.len());
        opt = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open("testin.test")
            .expect("Failed to open db file");
        opt.set_len(2048).unwrap();
        map = unsafe { memmap::MmapMut::map_mut(&opt) }.unwrap();
        println!("should be 5: {}", map[1023]);
        println!("new should be 0: {}", map[2047]);
        println!("len : {}", map.len());
    }

    fn db_fast_read_write_test_inner() -> Result<(), Box<dyn Error>> {
        let mut db = DB::open("test/test")?;
        for i in 0..150_000 {
            let key = format!("key_{}", i);
            let value = format!("value_{}", i);
            db.put(&key, &value)?;
        }

        for i in 0..150_000 {
            if i % 10 == 0 {
                let key = format!("key_{}", i);
                let _value = db.get(&key)?;
            }
        }

        Ok(())
    }
    #[test]
    fn db_fast_read_write_test() {
        let _ = fs::remove_dir_all("test");
        fs::create_dir("test").unwrap();
        db_fast_read_write_test_inner().unwrap();
    }
    
    fn _hash_test() {
        let mut foo = Vec::<u64>::new();
        let mut cnt = HashMap::new();
        let combs = combinations(3, None);
        for rng_string in combs {
            // let mut s = DefaultHasher::new();
            // rng_string.hash(&mut s);
            // foo.push(s.finish());

            foo.push(DB::get_hash(&rng_string) as u64);
        }


        let mut checked = Vec::<u64>::new();
        println!("{}", foo.len());
        for i in 0..foo.len() {
            if checked.contains(&foo[i]) {
                continue;
            }
            checked.push(foo[i]);
            let mut i_collisions = 0;
            for j in i + 1..foo.len() {
                if foo[i] == foo[j] {
                    i_collisions += 1;
                }
            }
            if i_collisions != 0 {
                cnt.insert(&foo[i], i_collisions);
            }
        }
        for entry in cnt.iter() {
            println!("{}: {}", entry.0, entry.1);
        }
    }
}
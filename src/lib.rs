extern crate core;

use memmap::{MmapMut, MmapOptions };
use std::{ fs::{ OpenOptions }, io::{ Seek, SeekFrom, Write } };
use std::error::Error;
use std::str;
mod mem_table;
mod db_options;

use crate::mem_table::{Entry, MemTable};

struct MmapControl {
    mmap: MmapMut,
    path: String,
}

impl MmapControl {
    fn clear(&mut self) {
        self.mmap.fill(0);
    }
}

impl MmapControl {
    fn new(mmap: MmapMut, path: String) -> MmapControl {
        return MmapControl {
            mmap,
            path
        };
    }
    
    fn len(&self) -> usize { self.mmap.len() }
    
    fn write(&mut self, offset: usize, data: &[u8]) {
        self.mmap[offset..offset + data.len() as usize].copy_from_slice(data);
    }
    
    fn read(&self, offset: usize, count: usize) -> &[u8] {
        return &self.mmap[offset..offset + count];
    }
    
    fn resize(&mut self, new_size: u64)  -> Result<(), Box<dyn Error>> {
        let db_options = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(self.path.to_string())
            .expect("Failed to open db file");
        db_options.set_len(new_size as u64)?;

        self.mmap = unsafe {
            MmapOptions::new()
                .map_mut(&db_options)
                .expect("Failed to map db file")
        };
        
        Ok(())
    }
}
struct PutResult {
    psl: u32
}

pub struct DB {
    support_memory: MmapControl,
    db_memory: MmapControl,
    mem_table: MemTable,
    max_psl: u32,
}

impl DB {
    const DB_SUPPORT_ENTRY_SIZE: usize = 
        Self::DB_SUPPORT_IS_OCCUPIED_END - Self::DB_SUPPORT_IS_OCCUPIED_START 
        +
        Self::DB_SUPPORT_PSL_END - Self::DB_SUPPORT_PSL_START
        +
        Self::DB_SUPPORT_KEY_START_END - Self::DB_SUPPORT_KEY_START_START
        +
        Self::DB_SUPPORT_KEY_END_END - Self::DB_SUPPORT_KEY_END_START
        +
        Self::DB_SUPPORT_VALUE_START_END - Self::DB_SUPPORT_VALUE_START_START
        +
        Self::DB_SUPPORT_VALUE_END_END - Self::DB_SUPPORT_VALUE_END_START;
    
    const DB_SUPPORT_IS_OCCUPIED_START: usize = 0;
    const DB_SUPPORT_IS_OCCUPIED_END: usize = 1;
    
    const DB_SUPPORT_PSL_START: usize = 1;
    const DB_SUPPORT_PSL_END: usize = 5;
    
    const DB_SUPPORT_KEY_START_START: usize = 5;
    const DB_SUPPORT_KEY_START_END: usize = 9;
    
    const DB_SUPPORT_KEY_END_START: usize = 9;
    const DB_SUPPORT_KEY_END_END: usize = 13;

    const DB_SUPPORT_VALUE_START_START: usize = 13;
    const DB_SUPPORT_VALUE_START_END: usize = 17;

    const DB_SUPPORT_VALUE_END_START: usize = 17;
    const DB_SUPPORT_VALUE_END_END: usize = 21;

    const DB_SUPPORT_VALUE_LEN_SIZE: usize = 4;
    const DB_SUPPORT_KEY_LEN_SIZE: usize = 4;
    
    pub fn open(path: &str) -> Result<DB, Box<dyn Error>> {
        let mut support_options = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path.to_string() + ".kvdbs")
            .expect("Failed to open db file");

        support_options.seek(SeekFrom::Start(0))?;
        let buf = vec![0; 64];
        support_options.write(&buf)?;
        support_options.seek(SeekFrom::Start(0))?;

        let support_memory = unsafe {
            MmapOptions::new()
                .map_mut(&support_options)
                .expect("Failed to map db file")
        };
        

        let mut db_options = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path.to_string() + ".kvdb")
            .expect("Failed to open db file");
        db_options.seek(SeekFrom::Start(0))?;
        db_options.write(&buf)?;
    
        let mut db_memory = unsafe {
            MmapOptions::new()
                .map_mut(&db_options)
                .expect("Failed to map db file")
        };
        db_memory[0..4].copy_from_slice(&[4, 0, 0, 0]);
        
        let db = DB {
            support_memory: MmapControl::new(support_memory, path.to_string() + ".kvdbs"),
            db_memory: MmapControl::new(db_memory, path.to_string() + ".kvdb"),
            mem_table: MemTable::new(),
            max_psl: 0
        };
        
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
                + Self::DB_SUPPORT_VALUE_LEN_SIZE 
                + Self::DB_SUPPORT_KEY_LEN_SIZE;
            
            if self.db_memory.len() < after_write_value_mem_addr_end {
                self.db_memory.resize((self.db_memory.len() * 2) as u64).unwrap();
            }
            
            let index = Self::align_hash(Self::get_hash(&self.mem_table.entries[i].key), self.support_memory.len() as u32) as usize;
            let max_after_write_support_memory_len = index + ((self.max_psl + 2) as usize * Self::DB_SUPPORT_ENTRY_SIZE);
            if self.support_memory.len() < max_after_write_support_memory_len {
                self.support_memory.resize((self.support_memory.len() * 2) as u64).unwrap();
                self.rehash_entries();
            }
            
            let result = Self::write_entry_internal(&mut self.db_memory, &mut self.support_memory, &self.mem_table.entries[i]).unwrap();
            if result.psl > self.max_psl {
                self.max_psl = result.psl;
            }
            i += 1;
        }
    }
    
    fn read_psl(mem: [u8; Self::DB_SUPPORT_ENTRY_SIZE]) -> u32 {
        return u32::from_le_bytes(
            mem[Self::DB_SUPPORT_PSL_START..Self::DB_SUPPORT_PSL_END]
            .try_into()
            .unwrap());
    }
    
    fn write_psl(mem: &mut [u8; Self::DB_SUPPORT_ENTRY_SIZE], psl: u32) {
        mem[Self::DB_SUPPORT_PSL_START..Self::DB_SUPPORT_PSL_END]
            .copy_from_slice(&psl.to_le_bytes());
    }
    
    fn set_occupied(mem: &mut [u8; Self::DB_SUPPORT_ENTRY_SIZE], occupied: bool) {
        if occupied {
            mem[Self::DB_SUPPORT_IS_OCCUPIED_START..Self::DB_SUPPORT_IS_OCCUPIED_END].copy_from_slice(&1u8.to_le_bytes());
        }
        else {
            mem[Self::DB_SUPPORT_IS_OCCUPIED_START..Self::DB_SUPPORT_IS_OCCUPIED_END].copy_from_slice(&0u8.to_le_bytes());
        }
    }
    
    fn read_key_start(mem: [u8; Self::DB_SUPPORT_ENTRY_SIZE]) -> u32 {
        return u32::from_le_bytes(
            mem[Self::DB_SUPPORT_KEY_START_START..Self::DB_SUPPORT_KEY_START_END]
            .try_into()
            .unwrap());
    }
    
    fn write_key_start(mem: &mut [u8; Self::DB_SUPPORT_ENTRY_SIZE], key_start: u32) {
        mem[Self::DB_SUPPORT_KEY_START_START..Self::DB_SUPPORT_KEY_START_END]
            .copy_from_slice(&key_start.to_le_bytes());
    }
    
    fn read_key_end(mem: [u8; Self::DB_SUPPORT_ENTRY_SIZE]) -> u32 {
        return u32::from_le_bytes(
            mem[Self::DB_SUPPORT_KEY_END_START..Self::DB_SUPPORT_KEY_END_END]
            .try_into()
            .unwrap());
    }
    
    fn write_key_end(mem: &mut [u8; Self::DB_SUPPORT_ENTRY_SIZE], key_end: u32) {
        mem[Self::DB_SUPPORT_KEY_END_START..Self::DB_SUPPORT_KEY_END_END]
            .copy_from_slice(&key_end.to_le_bytes());
    }
    
    fn read_value_start(mem: [u8; Self::DB_SUPPORT_ENTRY_SIZE]) -> u32 {
        return u32::from_le_bytes(
            mem[Self::DB_SUPPORT_VALUE_START_START..Self::DB_SUPPORT_VALUE_START_END]
            .try_into()
            .unwrap());
    }
    
    fn write_value_start(mem: &mut [u8; Self::DB_SUPPORT_ENTRY_SIZE], value_start: u32) {
        mem[Self::DB_SUPPORT_VALUE_START_START..Self::DB_SUPPORT_VALUE_START_END]
            .copy_from_slice(&value_start.to_le_bytes());
    }
    
    fn read_value_end(mem: [u8; Self::DB_SUPPORT_ENTRY_SIZE]) -> u32 {
        return u32::from_le_bytes(
            mem[Self::DB_SUPPORT_VALUE_END_START..Self::DB_SUPPORT_VALUE_END_END]
            .try_into()
            .unwrap());
    }
    
    fn write_value_end(mem: &mut [u8; Self::DB_SUPPORT_ENTRY_SIZE], value_end: u32) {
        mem[Self::DB_SUPPORT_VALUE_END_START..Self::DB_SUPPORT_VALUE_END_END]
            .copy_from_slice(&value_end.to_le_bytes());
    }
    
  
    
    fn write_entry_internal(db_memory: &mut MmapControl, support_memory: &mut MmapControl, entry: &Entry) -> Result<PutResult, Box<dyn Error>> {
        let key_hash = Self::get_hash(&entry.key);
        let mut aligned_index = Self::align_hash(key_hash, support_memory.len() as u32) as usize;

        let mut tmp_mem: [u8; Self::DB_SUPPORT_ENTRY_SIZE] = support_memory.read(aligned_index, Self::DB_SUPPORT_ENTRY_SIZE)
            .try_into()
            .unwrap();
        let value_mem_addr_end = u32::from_le_bytes(db_memory.read(0, 4).try_into().unwrap());

        let key_start = value_mem_addr_end;
        let key_end = key_start + entry.key.len() as u32;
        db_memory.write(key_start as usize, entry.key.as_bytes());

        Self::write_key_start(&mut tmp_mem, key_start);
        Self::write_key_end(&mut tmp_mem, key_end);
        
        let value_start: u32 = key_end;
        let mut value_end = value_start + entry.value.len() as u32;
        Self::write_value_start(&mut tmp_mem, value_start);
        Self::write_value_end(&mut tmp_mem, value_end);
        

        db_memory.write(value_start as usize, entry.value.as_bytes());
        db_memory.write(value_end as usize, &(entry.key.len() as u32).to_le_bytes());
        value_end += 4;
        db_memory.write(value_end as usize, &(entry.value.len() as u32).to_le_bytes());
        value_end += 4;
        
        Self::set_occupied(&mut tmp_mem, true);
        db_memory.write(0, &value_end.to_le_bytes());
        
        let mut mem: [u8; Self::DB_SUPPORT_ENTRY_SIZE] = support_memory.read(aligned_index, Self::DB_SUPPORT_ENTRY_SIZE)
            .try_into()
            .unwrap();
        
        let mut is_occupied = mem[0] == 1u8;
        let mut v_psl = 0;
        while is_occupied {
            v_psl += 1;
            aligned_index += Self::DB_SUPPORT_ENTRY_SIZE;
            mem = support_memory.read(aligned_index, Self::DB_SUPPORT_ENTRY_SIZE)
                .try_into()
                .unwrap();
            is_occupied = mem[0] == 1u8;
            if is_occupied {
                let f_psl = Self::read_psl(mem);
                if v_psl > f_psl {
                    Self::write_psl(&mut tmp_mem, v_psl);
                    support_memory.write(aligned_index, &tmp_mem);
                    tmp_mem[0..Self::DB_SUPPORT_ENTRY_SIZE].copy_from_slice(&mem);
                    v_psl = f_psl;
                }
            }
        }
        
        Self::write_psl(&mut tmp_mem, v_psl);
        support_memory.write(aligned_index, &tmp_mem);
        
        Ok(PutResult { psl: v_psl })
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
        return hash;    // todo return hash instead of 0
    }
    
    fn align_hash(hash: u32, file_size: u32) -> u32 {
        return (hash - (hash % Self::DB_SUPPORT_ENTRY_SIZE as u32)) % (file_size - (file_size % Self::DB_SUPPORT_ENTRY_SIZE as u32));
    }
    
    pub fn get(&self, key: &String) -> Result<String, Box<dyn Error>> {
        match self.mem_table.get(&key) {
            None => {}
            Some(value) => { return Ok(value.to_string()); }
        };
        
        let hash = Self::get_hash(&key);
        let mut aligned_index = Self::align_hash(hash, self.support_memory.len() as u32) as usize;
        let mut mem: [u8; Self::DB_SUPPORT_ENTRY_SIZE] = self.support_memory.read(aligned_index, Self::DB_SUPPORT_ENTRY_SIZE)
            .try_into()
            .unwrap();
        
        let mut is_occupied = mem[0] == 1u8;
        if !is_occupied {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "Key not found")));
        }
        
        let mut key_start: u32 = Self::read_key_start(mem);
        let mut key_end: u32 = Self::read_key_end(mem);
        let mut founded_key = str::from_utf8(&self.db_memory.read(key_start as usize, (key_end - key_start) as usize)).unwrap();
        
        while founded_key != key && is_occupied {
            aligned_index += Self::DB_SUPPORT_ENTRY_SIZE;
            mem = self.support_memory.read(aligned_index, Self::DB_SUPPORT_ENTRY_SIZE)
                .try_into()
                .unwrap();
            is_occupied = mem[0] == 1u8;
            key_start = Self::read_key_start(mem);
            key_end = Self::read_key_end(mem);
            founded_key = str::from_utf8(&self.db_memory.read(key_start as usize, (key_end - key_start) as usize)).unwrap();
            
        }
        
        if !is_occupied {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, format!("Key {} not found", key))));
        }

        let value_start: u32 = Self::read_value_start(mem);
        let value_end: u32 = Self::read_value_end(mem);
        let value = str::from_utf8(&self.db_memory.read(value_start as usize, (value_end - value_start) as usize)).unwrap();
        
        return Ok(value.to_string());
    }
    
    fn rehash_entries(&mut self) {
        self.support_memory.clear();
        self.max_psl = 0;
        let mut pointer = u32::from_le_bytes(self.db_memory.read(0, 4).try_into().unwrap());
        while pointer > 4 {
            let value_len = 
                u32::from_le_bytes(self.db_memory.read((pointer as usize) - Self::DB_SUPPORT_VALUE_LEN_SIZE, 4)
                    .try_into()
                    .unwrap());
            let value_start = pointer - value_len - Self::DB_SUPPORT_VALUE_LEN_SIZE as u32 - Self::DB_SUPPORT_KEY_LEN_SIZE as u32;
            
            let key_len = u32::from_le_bytes(self.db_memory.read((pointer as usize) - Self::DB_SUPPORT_VALUE_LEN_SIZE - Self::DB_SUPPORT_KEY_LEN_SIZE, 4).try_into().unwrap());
            let key_start = ((pointer as usize) - Self::DB_SUPPORT_VALUE_LEN_SIZE - Self::DB_SUPPORT_KEY_LEN_SIZE) as u32 - value_len - key_len;
            
            let key = str::from_utf8(self.db_memory.read(key_start as usize, key_len as usize)).unwrap();
            let mut aligned_index = Self::align_hash(Self::get_hash(&key.to_string()), self.support_memory.len() as u32) as usize;
            
            let mut mem: [u8; Self::DB_SUPPORT_ENTRY_SIZE] = self.support_memory.read(aligned_index as usize, Self::DB_SUPPORT_ENTRY_SIZE)
                .try_into()
                .unwrap();
            
            let mut tmp_mem: [u8; Self::DB_SUPPORT_ENTRY_SIZE] = self.support_memory.read(aligned_index as usize, Self::DB_SUPPORT_ENTRY_SIZE)
                .try_into()
                .unwrap();
            tmp_mem[0] = 1u8;
            Self::write_key_start(&mut tmp_mem, key_start);
            Self::write_key_end(&mut tmp_mem, key_start + key_len);
            Self::write_value_start(&mut tmp_mem, value_start);
            Self::write_value_end(&mut tmp_mem, value_start + value_len);
            
            let mut is_occupied = mem[0] == 1u8;
            let mut v_psl = 0;
            while is_occupied {
                v_psl += 1;
                aligned_index += Self::DB_SUPPORT_ENTRY_SIZE;
                mem = self.support_memory.read(aligned_index, Self::DB_SUPPORT_ENTRY_SIZE)
                    .try_into()
                    .unwrap();
                is_occupied = mem[0] == 1u8;
                if is_occupied {
                    let f_psl = Self::read_psl(mem);
                    if v_psl > f_psl {
                        Self::write_psl(&mut tmp_mem, v_psl);
                        self.support_memory.write(aligned_index, &tmp_mem);
                        tmp_mem[0..Self::DB_SUPPORT_ENTRY_SIZE].copy_from_slice(&mem);
                        v_psl = f_psl;
                    }
                }
            }

            Self::write_psl(&mut tmp_mem, v_psl);
            if v_psl > self.max_psl {
                self.max_psl = v_psl;
            }
            
            self.support_memory.write(aligned_index, &tmp_mem);
            pointer -= value_len + key_len + ((Self::DB_SUPPORT_VALUE_LEN_SIZE + Self::DB_SUPPORT_KEY_LEN_SIZE) as u32);
        }
    }
}

mod tests {
    use std::collections::HashMap;
    use std::error::Error;
    use std::{fs, panic};
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
                if g.len() == 0{
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
    
    #[test]
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
    
    fn db_fast_read_write_test_inner() -> Result<(), Box<dyn Error>>{
        let mut db = DB::open("test/test")?;
        for i in 0..15_000 {
            let key = format!("key_{}", i);
            let value = format!("value_{}", i);
            db.put(&key, &value)?;
        }

        for i in 0..15_000 {
            if i % 1 == 0 {
                let key = format!("key_{}", i);
                println!("{}", db.get(&key)?);
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
    
    #[test]
    fn hash_test() {
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
            for j in i+1..foo.len() {
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
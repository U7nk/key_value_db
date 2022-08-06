use memmap::{ MmapMut, MmapOptions };
use std::{ fs::{ OpenOptions }, io::{ Seek, SeekFrom, Write } };
use std::error::Error;
use std::fs::File;
use std::ops::Range;
use std::os::windows::fs::FileExt;
use std::ptr::hash;
use std::str;
mod mem_table;
mod db_options;

use crate::mem_table::{Entry, MemTable};



pub struct DB {
    support_memory: MmapMut,
    db_memory: MmapMut,
    mem_table: MemTable,
    path: String,
}

impl DB {
    const DB_SUPPORT_ENTRY_SIZE: usize = Self::DB_SUPPORT_IS_OCCUPIED_END - Self::DB_SUPPORT_IS_OCCUPIED_START 
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
    
    pub fn open(path: &str) -> Result<DB, Box<dyn Error>> {
        let mut support_options = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path.to_string() + ".kvdb")
            .expect("Failed to open db file");

        support_options.seek(SeekFrom::Start(0))?;
        let buf = vec![0; 1024 * 1024 * 2 * 4];
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
            .open(path.to_string() + ".kvdbs")
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
            support_memory,
            db_memory,
            mem_table: MemTable::new(),
            path: path.to_string(),
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
        
        for entry in &self.mem_table.entries {
            let mut value_mem_addr_end = u32::from_le_bytes(self.db_memory[0..4]
                .try_into()
                .unwrap()) as usize;
            if entry.key == "key_105411" {
                println!("{}", value_mem_addr_end);
            }
            if self.db_memory.len() - 300 < value_mem_addr_end + entry.key.len() + entry.value.len() + 8 {
                let resized_file = self.resize_file(self.db_memory.len() as u32 * 2);
                self.db_memory = unsafe {
                    MmapOptions::new()
                        .map_mut(&resized_file)
                        .expect("Failed to map db file")
                };
                println!("{}", self.db_memory.len());
                value_mem_addr_end = u32::from_le_bytes(self.db_memory[0..4]
                    .try_into()
                    .unwrap()) as usize;
                println!("{}", value_mem_addr_end);
            }
            Self::write(&mut self.support_memory, &mut self.db_memory, entry);
        }
        
        self.mem_table.entries.clear();
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
    
    
    fn write(support_memory: &mut MmapMut, db_memory: &mut MmapMut, entry: &Entry) {
        let key_hash = Self::get_hash(&entry.key);
        let mut aligned_index = Self::align_hash(key_hash) as usize;


        let mut tmp_mem: [u8; Self::DB_SUPPORT_ENTRY_SIZE] = support_memory[aligned_index..aligned_index + Self::DB_SUPPORT_ENTRY_SIZE]
            .try_into()
            .unwrap();
        let value_mem_addr_end = u32::from_le_bytes(db_memory[0..4]
            .try_into()
            .unwrap());

        let key_start = value_mem_addr_end;
        let key_end = key_start + entry.key.len() as u32;
        db_memory[key_start as usize..key_end as usize]
            .copy_from_slice(entry.key.as_bytes());

        Self::write_key_start(&mut tmp_mem, key_start);
        Self::write_key_end(&mut tmp_mem, key_end);

        let value_start: u32 = key_end;
        let value_end = value_start + entry.value.len() as u32;
        Self::write_value_start(&mut tmp_mem, value_start);
        Self::write_value_end(&mut tmp_mem, value_end);

        db_memory[value_start as usize..value_end as usize]
            .copy_from_slice(entry.value.as_bytes());
        
        Self::set_occupied(&mut tmp_mem, true);
        db_memory[0..4].copy_from_slice(&value_end.to_le_bytes());
        
        let mut mem: [u8; Self::DB_SUPPORT_ENTRY_SIZE] = support_memory[aligned_index..aligned_index + Self::DB_SUPPORT_ENTRY_SIZE]
            .try_into()
            .unwrap();
        
        let mut is_occupied = mem[0] == 1u8;
        let mut v_psl = 0;
        while is_occupied {
            v_psl += 1;
            aligned_index += Self::DB_SUPPORT_ENTRY_SIZE;
            mem = support_memory[aligned_index..aligned_index + Self::DB_SUPPORT_ENTRY_SIZE]
                .try_into()
                .unwrap();
            is_occupied = mem[0] == 1u8;
            if is_occupied {
                let f_psl = Self::read_psl(mem);
                if v_psl > f_psl {
                    Self::write_psl(&mut tmp_mem, v_psl);
                    support_memory[aligned_index..aligned_index + Self::DB_SUPPORT_ENTRY_SIZE]
                        .copy_from_slice(&tmp_mem);
                    tmp_mem[0..Self::DB_SUPPORT_ENTRY_SIZE].copy_from_slice(&mem);
                    v_psl = f_psl;
                }
            }
        }
        Self::write_psl(&mut tmp_mem, v_psl);
        support_memory[aligned_index..aligned_index + Self::DB_SUPPORT_ENTRY_SIZE]
            .copy_from_slice(&tmp_mem);
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
        return 0;    // todo return hash instead of 0
    }
    
    fn align_hash(hash: u32) -> u32 {
        return (hash - (hash % Self::DB_SUPPORT_ENTRY_SIZE as u32)) % 2_700_000;
    }
    
    pub fn get(&self, key: &String) -> Result<String, Box<dyn Error>> {
        match self.mem_table.get(&key) {
            None => {}
            Some(value) => { return Ok(value.to_string()); }
        };
        
        let hash = Self::get_hash(&key);
        let mut aligned_index = Self::align_hash(hash) as usize;
        let mut mem: [u8; Self::DB_SUPPORT_ENTRY_SIZE] = self.support_memory[aligned_index..aligned_index + Self::DB_SUPPORT_ENTRY_SIZE]
            .try_into()
            .unwrap();
        
        let mut is_occupied = mem[0] == 1u8;
        if !is_occupied {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "Key not found")));
        }
        
        let mut key_start: u32 = Self::read_key_start(mem);
        let mut key_end: u32 = Self::read_key_end(mem);
        let mut founded_key = str::from_utf8(&self.db_memory[key_start as usize..key_end as usize])
            .unwrap();
        
        while founded_key != key && is_occupied {
            aligned_index += Self::DB_SUPPORT_ENTRY_SIZE;
            mem = self.support_memory[aligned_index..aligned_index + Self::DB_SUPPORT_ENTRY_SIZE]
                .try_into()
                .unwrap();
            is_occupied = mem[0] == 1u8;
            key_start = Self::read_key_start(mem);
            key_end = Self::read_key_end(mem);
            founded_key = str::from_utf8(&self.db_memory[key_start as usize..key_end as usize])
                .unwrap();
            
        }
        
        if !is_occupied {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "Key not found")));
        }

        let value_start: u32 = Self::read_value_start(mem);
        let value_end: u32 = Self::read_value_end(mem);
        let value = String::from_utf8(self.db_memory[value_start as usize..value_end as usize].to_vec())
            .unwrap();
        
        return Ok(value);
    }
    
    fn resize_file(&self, size: u32) -> File {
        let mut db_options = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(self.path.to_string() + ".kvdb")
            .expect("Failed to open db file");
        db_options.seek(SeekFrom::Start(size as u64)).unwrap();
        db_options.write_all(&[0]).unwrap();
        db_options.seek(SeekFrom::Start(0)).unwrap();
        db_options.sync_all().unwrap();
        return db_options;
    }
}

mod tests{
    use std::collections::HashMap;
    use crate::DB;

    fn combinations(len: u32, mem: Option<&mut HashMap<u32, Vec<String>>>) -> Vec<String> {
        let x = &mut HashMap::new();
        let mut _mem = mem.unwrap_or(x);
        if _mem.contains_key(&len){
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
    fn file_resize_first_4_bytes_value_bug(){
        let mut db = DB::open("test.kvdb")
            .unwrap();
        
        db.put(&String::from("key"), &String::from("value"))
            .unwrap();
        db.put(&String::from("key"), &String::from("value"))
            .unwrap();
        db.resize_file((db.db_memory.len() * 3) as u32);
        let res = db.get(&"key".to_string());
        assert_eq!(res.unwrap(), "value".to_string());
    }
    
    #[test]
    fn db_fast_read_write_test(){
        let mut db = DB::open("test").unwrap();
        for i in 0..150_000 {
            let key = format!("key_{}", i);
            let value = format!("value_{}", i);
            db.put(&key, &value).unwrap();
        }

        for i in 0..150_000 {
            if i % 100 == 0 {
                let key = format!("key_{}", i);
                println!("{}", db.get(&key).unwrap());
            }
            
            
        }
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
        
        
      
        // 1 2 2 2 2
        let mut collisions = 0;
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
                collisions += 1;
                cnt.insert(&foo[i], i_collisions);
            }
            
        }
        for entry in cnt.iter() {
            println!("{}: {}", entry.0, entry.1);
        }
    }
}
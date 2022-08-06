use std::cmp::Ordering;
use std::vec::Vec;


pub struct Entry {
    pub key: String,
    pub value: String,
}

impl Eq for Entry { }

impl PartialEq<Self> for Entry {
    fn eq(&self, other: &Self) -> bool {
        return self.key == other.key;
    }
}

impl PartialOrd<Self> for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        return Some(self.key.cmp(&other.key));
    }
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> Ordering {
        return self.key.cmp(&other.key);
    }
}
pub struct MemTable {
    pub entries: Vec<Entry>,
}

impl<'mem_table> MemTable {
    
    pub fn new() -> MemTable {
        return MemTable {
            entries: Vec::new(),
        };
    }

    pub fn insert(&mut self, key: &String, value: &String) -> bool {
        self.entries.push(Entry {
            key: key.to_string(),
            value: value.to_string(),
        });
        
        self.entries.sort();
        if self.entries.len() == 1 {
            return true;
        }

        return false;
    }
    
    pub fn get(&self, key: &String) -> Option<&String> {
        let mut i = 0;
        while i < self.entries.len() {
            if self.entries[i].key == *key {
                return Some(&self.entries[i].value);
            }
            i += 1;
        }
        return None;
    }
}



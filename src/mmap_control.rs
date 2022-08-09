use std::error::Error;
use std::fs::OpenOptions;
use memmap::{MmapMut, MmapOptions};
use crate::SupportEntry;

pub struct MmapControl {
    mmap: MmapMut,
    path: String,
}

impl MmapControl {
    pub(crate) fn clear(&mut self) {
        self.mmap.fill(0);
    }

    pub(crate) fn new(path: String, size: u64) -> MmapControl {
        let options = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .expect("Failed to open db file");
        options.set_len(size).unwrap();
        
        let mmap = unsafe {
            MmapOptions::new()
                .map_mut(&options)
                .expect("Failed to map db file")
        };
        
        return MmapControl {
            mmap,
            path
        };
    }

    pub(crate) fn len(&self) -> usize { self.mmap.len() }

    pub(crate) fn write(&mut self, offset: usize, data: &[u8]) {
        self.mmap[offset..offset + data.len() as usize].copy_from_slice(data);
    }

    pub(crate) fn read(&self, offset: usize, count: usize) -> &[u8] {
        return &self.mmap[offset..offset + count];
    }

    pub(crate) fn read_support_entry(&self, offset: usize) -> SupportEntry {
        return SupportEntry::new(self.mmap[offset..offset + SupportEntry::DB_SUPPORT_ENTRY_SIZE]
            .try_into()
            .unwrap());
    }
    
    pub(crate) fn read_value(&self, entry: &SupportEntry) -> &[u8] {
        return &self.mmap[entry.value_start as usize..entry.value_end as usize];
    }
    
    pub(crate) fn read_key(&self, entry: &SupportEntry) -> &[u8] {
        return &self.mmap[entry.key_start as usize..entry.key_end as usize];
    }
    
    pub(crate) fn write_value(&mut self, entry: &SupportEntry, data: &[u8]) {
        self.mmap[entry.value_start as usize..entry.value_end as usize].copy_from_slice(data);
    }
    
    pub(crate) fn write_key(&mut self, entry: &SupportEntry, data: &[u8]) {
        self.mmap[entry.key_start as usize..entry.key_end as usize].copy_from_slice(data);
    }
    
    
    
    pub(crate) fn resize(&mut self, new_size: u64) -> Result<(), Box<dyn Error>> {
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
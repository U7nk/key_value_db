

pub(crate) struct SupportEntry {
    pub(crate) is_occupied: bool,
    pub(crate) probe_sequence_length: u32,
    pub(crate) key_start: u32,
    pub(crate) key_end: u32,
    pub(crate) value_start: u32,
    pub(crate) value_end: u32,
}

impl SupportEntry {
    
    pub(crate) const DB_SUPPORT_ENTRY_SIZE: usize =
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
    pub(crate) fn new(mem: [u8; Self::DB_SUPPORT_ENTRY_SIZE]) -> SupportEntry {
        return SupportEntry {
            is_occupied: mem[0] == 1,
            probe_sequence_length: u32::from_le_bytes([mem[1], mem[2], mem[3], mem[4]]),
            key_start: u32::from_le_bytes([mem[5], mem[6], mem[7], mem[8]]),
            key_end: u32::from_le_bytes([mem[9], mem[10], mem[11], mem[12]]),
            value_start: u32::from_le_bytes([mem[13], mem[14], mem[15], mem[16]]),
            value_end: u32::from_le_bytes([mem[17], mem[18], mem[19], mem[20]]),
        };
    }
    
    pub(crate) fn to_bytes(&self) -> [u8; Self::DB_SUPPORT_ENTRY_SIZE] {
        let mut mem: [u8; Self::DB_SUPPORT_ENTRY_SIZE] = [0; Self::DB_SUPPORT_ENTRY_SIZE];
        mem[0] = if self.is_occupied { 1 } else { 0 };
        mem[1..5].copy_from_slice(self.probe_sequence_length.to_le_bytes().as_slice());
        mem[5..9].copy_from_slice(self.key_start.to_le_bytes().as_slice());
        mem[9..13].copy_from_slice(self.key_end.to_le_bytes().as_slice());
        mem[13..17].copy_from_slice(self.value_start.to_le_bytes().as_slice());
        mem[17..21].copy_from_slice(self.value_end.to_le_bytes().as_slice());
        return mem;
    }
}
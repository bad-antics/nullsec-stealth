# NullSec StegoHide - Advanced Steganography Tool
# Language: Crystal
# Author: bad-antics
# License: NullSec Proprietary

require "openssl"
require "base64"
require "option_parser"

module NullSec
  VERSION = "1.0.0"
  MAGIC = "NULLSTEG"
  
  # Encryption handler using AES-256-GCM
  class Crypto
    def initialize(@key : String)
      @derived_key = derive_key(@key)
    end
    
    private def derive_key(password : String) : Bytes
      # PBKDF2 key derivation
      OpenSSL::PKCS5.pbkdf2_hmac(
        password,
        "nullsec_salt_v1",
        iterations: 100000,
        dk_len: 32,
        digest: OpenSSL::Digest.new("SHA256")
      )
    end
    
    def encrypt(data : Bytes) : Bytes
      cipher = OpenSSL::Cipher.new("aes-256-gcm")
      cipher.encrypt
      
      iv = Random::Secure.random_bytes(12)
      cipher.key = @derived_key
      cipher.iv = iv
      
      encrypted = cipher.update(data)
      encrypted += cipher.final
      
      tag = cipher.auth_tag(16)
      
      # Format: IV (12) + Tag (16) + Encrypted Data
      io = IO::Memory.new
      io.write(iv)
      io.write(tag)
      io.write(encrypted)
      io.to_slice
    end
    
    def decrypt(data : Bytes) : Bytes
      raise "Data too short" if data.size < 28
      
      iv = data[0, 12]
      tag = data[12, 16]
      encrypted = data[28..]
      
      cipher = OpenSSL::Cipher.new("aes-256-gcm")
      cipher.decrypt
      cipher.key = @derived_key
      cipher.iv = iv
      cipher.auth_tag = tag
      
      decrypted = cipher.update(encrypted)
      decrypted += cipher.final
      decrypted
    end
  end
  
  # PNG LSB Steganography
  class PNGStego
    PNG_SIGNATURE = Bytes[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
    
    struct Chunk
      property type : String
      property data : Bytes
      property crc : UInt32
      
      def initialize(@type, @data, @crc)
      end
    end
    
    def initialize(@verbose : Bool = false)
    end
    
    def encode(cover_path : String, secret : Bytes, output_path : String)
      cover_data = File.read(cover_path).to_slice
      
      # Verify PNG signature
      unless cover_data[0, 8] == PNG_SIGNATURE
        raise "Invalid PNG file"
      end
      
      log "Reading PNG chunks..."
      chunks = parse_chunks(cover_data[8..])
      
      # Find IDAT chunks for embedding
      idat_indices = chunks.each_with_index.select { |c, _| c.type == "IDAT" }.map(&.[1]).to_a
      
      if idat_indices.empty?
        raise "No IDAT chunks found"
      end
      
      # Calculate available capacity
      total_idat_size = idat_indices.sum { |i| chunks[i].data.size }
      capacity = total_idat_size / 8  # 1 bit per byte
      
      # Prepare payload with header
      payload = prepare_payload(secret)
      
      if payload.size > capacity
        raise "Secret too large. Capacity: #{capacity} bytes, Need: #{payload.size} bytes"
      end
      
      log "Embedding #{payload.size} bytes into #{total_idat_size} carrier bytes..."
      
      # Embed using LSB
      embedded_data = embed_lsb(chunks, idat_indices, payload)
      
      # Reconstruct PNG
      output = IO::Memory.new
      output.write(PNG_SIGNATURE)
      
      chunks.each_with_index do |chunk, idx|
        if idat_indices.includes?(idx)
          write_chunk(output, chunk.type, embedded_data.shift(chunk.data.size))
        else
          write_chunk(output, chunk.type, chunk.data)
        end
      end
      
      File.write(output_path, output.to_slice)
      log "Successfully encoded to #{output_path}"
    end
    
    def decode(stego_path : String) : Bytes
      stego_data = File.read(stego_path).to_slice
      
      unless stego_data[0, 8] == PNG_SIGNATURE
        raise "Invalid PNG file"
      end
      
      log "Reading PNG chunks..."
      chunks = parse_chunks(stego_data[8..])
      
      idat_indices = chunks.each_with_index.select { |c, _| c.type == "IDAT" }.map(&.[1]).to_a
      
      # Extract LSB data
      extracted = extract_lsb(chunks, idat_indices)
      
      # Parse header and extract payload
      parse_payload(extracted)
    end
    
    private def parse_chunks(data : Bytes) : Array(Chunk)
      chunks = [] of Chunk
      offset = 0
      
      while offset < data.size
        length = (data[offset].to_u32 << 24) |
                 (data[offset + 1].to_u32 << 16) |
                 (data[offset + 2].to_u32 << 8) |
                 data[offset + 3].to_u32
        
        type = String.new(data[offset + 4, 4])
        chunk_data = data[offset + 8, length]
        crc = (data[offset + 8 + length].to_u32 << 24) |
              (data[offset + 9 + length].to_u32 << 16) |
              (data[offset + 10 + length].to_u32 << 8) |
              data[offset + 11 + length].to_u32
        
        chunks << Chunk.new(type, chunk_data, crc)
        offset += 12 + length
        
        break if type == "IEND"
      end
      
      chunks
    end
    
    private def write_chunk(io : IO, type : String, data : Bytes)
      # Length
      io.write_bytes(data.size.to_u32, IO::ByteFormat::BigEndian)
      
      # Type
      io.write(type.to_slice)
      
      # Data
      io.write(data)
      
      # CRC
      crc_data = IO::Memory.new
      crc_data.write(type.to_slice)
      crc_data.write(data)
      crc = Zlib.crc32(crc_data.to_slice)
      io.write_bytes(crc.to_u32, IO::ByteFormat::BigEndian)
    end
    
    private def prepare_payload(secret : Bytes) : Bytes
      io = IO::Memory.new
      io.write(MAGIC.to_slice)
      io.write_bytes(secret.size.to_u32, IO::ByteFormat::BigEndian)
      io.write(secret)
      io.to_slice
    end
    
    private def embed_lsb(chunks : Array(Chunk), idat_indices : Array(Int32), payload : Bytes) : Array(Bytes)
      result = [] of Bytes
      bit_index = 0
      
      idat_indices.each do |idx|
        chunk_data = chunks[idx].data.dup
        
        chunk_data.size.times do |i|
          if bit_index < payload.size * 8
            byte_idx = bit_index // 8
            bit_pos = 7 - (bit_index % 8)
            bit = (payload[byte_idx] >> bit_pos) & 1
            
            chunk_data[i] = (chunk_data[i] & 0xFE) | bit
            bit_index += 1
          end
        end
        
        result << chunk_data
      end
      
      result
    end
    
    private def extract_lsb(chunks : Array(Chunk), idat_indices : Array(Int32)) : Bytes
      bits = [] of UInt8
      
      idat_indices.each do |idx|
        chunks[idx].data.each do |byte|
          bits << (byte & 1).to_u8
        end
      end
      
      # Convert bits to bytes
      result = Bytes.new(bits.size // 8)
      result.size.times do |i|
        byte = 0_u8
        8.times do |j|
          byte |= (bits[i * 8 + j] << (7 - j))
        end
        result[i] = byte
      end
      
      result
    end
    
    private def parse_payload(data : Bytes) : Bytes
      magic = String.new(data[0, 8])
      
      unless magic == MAGIC
        raise "No hidden data found or invalid format"
      end
      
      length = (data[8].to_u32 << 24) |
               (data[9].to_u32 << 16) |
               (data[10].to_u32 << 8) |
               data[11].to_u32
      
      data[12, length]
    end
    
    private def log(msg : String)
      puts "[*] #{msg}" if @verbose
    end
  end
  
  # Audio Steganography (WAV)
  class WAVStego
    WAV_HEADER_SIZE = 44
    
    def initialize(@verbose : Bool = false)
    end
    
    def encode(cover_path : String, secret : Bytes, output_path : String)
      cover_data = File.read(cover_path).to_slice
      
      # Verify WAV header
      unless String.new(cover_data[0, 4]) == "RIFF" && String.new(cover_data[8, 4]) == "WAVE"
        raise "Invalid WAV file"
      end
      
      log "Parsing WAV header..."
      
      # Get audio data section
      data_offset = find_wav_data_chunk(cover_data)
      audio_data = cover_data[data_offset..].dup
      
      # Calculate capacity
      capacity = audio_data.size / 8
      payload = prepare_payload(secret)
      
      if payload.size > capacity
        raise "Secret too large. Capacity: #{capacity} bytes"
      end
      
      log "Embedding #{payload.size} bytes into audio stream..."
      
      # Embed using LSB
      embedded = embed_lsb_audio(audio_data, payload)
      
      # Write output
      output = IO::Memory.new
      output.write(cover_data[0, data_offset])
      output.write(embedded)
      
      File.write(output_path, output.to_slice)
      log "Successfully encoded to #{output_path}"
    end
    
    def decode(stego_path : String) : Bytes
      stego_data = File.read(stego_path).to_slice
      
      unless String.new(stego_data[0, 4]) == "RIFF"
        raise "Invalid WAV file"
      end
      
      data_offset = find_wav_data_chunk(stego_data)
      audio_data = stego_data[data_offset..]
      
      extracted = extract_lsb_audio(audio_data)
      parse_payload(extracted)
    end
    
    private def find_wav_data_chunk(data : Bytes) : Int32
      offset = 12
      while offset < data.size - 8
        chunk_id = String.new(data[offset, 4])
        chunk_size = (data[offset + 4].to_u32) |
                     (data[offset + 5].to_u32 << 8) |
                     (data[offset + 6].to_u32 << 16) |
                     (data[offset + 7].to_u32 << 24)
        
        if chunk_id == "data"
          return offset + 8
        end
        
        offset += 8 + chunk_size
      end
      
      raise "No data chunk found"
    end
    
    private def prepare_payload(secret : Bytes) : Bytes
      io = IO::Memory.new
      io.write(MAGIC.to_slice)
      io.write_bytes(secret.size.to_u32, IO::ByteFormat::BigEndian)
      io.write(secret)
      io.to_slice
    end
    
    private def embed_lsb_audio(audio : Bytes, payload : Bytes) : Bytes
      result = audio.dup
      bit_index = 0
      
      result.size.times do |i|
        break if bit_index >= payload.size * 8
        
        byte_idx = bit_index // 8
        bit_pos = 7 - (bit_index % 8)
        bit = (payload[byte_idx] >> bit_pos) & 1
        
        result[i] = (result[i] & 0xFE) | bit
        bit_index += 1
      end
      
      result
    end
    
    private def extract_lsb_audio(audio : Bytes) : Bytes
      # Extract enough bits to get header + reasonable payload
      max_bytes = Math.min(audio.size / 8, 1024 * 1024)
      
      result = Bytes.new(max_bytes)
      max_bytes.times do |i|
        byte = 0_u8
        8.times do |j|
          byte |= ((audio[i * 8 + j] & 1) << (7 - j))
        end
        result[i] = byte
      end
      
      result
    end
    
    private def parse_payload(data : Bytes) : Bytes
      magic = String.new(data[0, 8])
      
      unless magic == MAGIC
        raise "No hidden data found"
      end
      
      length = (data[8].to_u32 << 24) |
               (data[9].to_u32 << 16) |
               (data[10].to_u32 << 8) |
               data[11].to_u32
      
      data[12, length]
    end
    
    private def log(msg : String)
      puts "[*] #{msg}" if @verbose
    end
  end
  
  class CLI
    def run
      mode = ""
      input_file = ""
      cover_file = ""
      output_file = ""
      key = ""
      format = "png"
      verbose = false
      
      parser = OptionParser.new do |p|
        p.banner = banner
        
        p.on("-m MODE", "--mode=MODE", "Mode: encode/decode") { |m| mode = m }
        p.on("-i FILE", "--input=FILE", "Input secret file (encode) or stego file (decode)") { |f| input_file = f }
        p.on("-c FILE", "--cover=FILE", "Cover file for encoding") { |f| cover_file = f }
        p.on("-o FILE", "--output=FILE", "Output file") { |f| output_file = f }
        p.on("-k KEY", "--key=KEY", "Encryption key") { |k| key = k }
        p.on("-f FORMAT", "--format=FORMAT", "Format: png/wav (default: auto)") { |f| format = f }
        p.on("-v", "--verbose", "Verbose output") { verbose = true }
        p.on("-h", "--help", "Show help") { puts p; exit }
      end
      
      parser.parse
      
      if mode.empty?
        puts parser
        exit 1
      end
      
      case mode.downcase
      when "encode"
        encode(input_file, cover_file, output_file, key, format, verbose)
      when "decode"
        decode(input_file, output_file, key, format, verbose)
      else
        puts "Unknown mode: #{mode}"
        exit 1
      end
    end
    
    private def encode(input : String, cover : String, output : String, key : String, format : String, verbose : Bool)
      raise "Missing input file" if input.empty?
      raise "Missing cover file" if cover.empty?
      raise "Missing output file" if output.empty?
      
      secret = File.read(input).to_slice
      
      # Encrypt if key provided
      if !key.empty?
        puts "[*] Encrypting payload..." if verbose
        crypto = Crypto.new(key)
        secret = crypto.encrypt(secret)
      end
      
      # Auto-detect format
      detected_format = if cover.ends_with?(".png")
        "png"
      elsif cover.ends_with?(".wav")
        "wav"
      else
        format
      end
      
      case detected_format
      when "png"
        stego = PNGStego.new(verbose)
        stego.encode(cover, secret, output)
      when "wav"
        stego = WAVStego.new(verbose)
        stego.encode(cover, secret, output)
      else
        raise "Unsupported format: #{detected_format}"
      end
      
      puts "[+] Encoding complete: #{output}"
    end
    
    private def decode(input : String, output : String, key : String, format : String, verbose : Bool)
      raise "Missing input file" if input.empty?
      raise "Missing output file" if output.empty?
      
      # Auto-detect format
      detected_format = if input.ends_with?(".png")
        "png"
      elsif input.ends_with?(".wav")
        "wav"
      else
        format
      end
      
      secret = case detected_format
      when "png"
        stego = PNGStego.new(verbose)
        stego.decode(input)
      when "wav"
        stego = WAVStego.new(verbose)
        stego.decode(input)
      else
        raise "Unsupported format: #{detected_format}"
      end
      
      # Decrypt if key provided
      if !key.empty?
        puts "[*] Decrypting payload..." if verbose
        crypto = Crypto.new(key)
        secret = crypto.decrypt(secret)
      end
      
      File.write(output, secret)
      puts "[+] Decoding complete: #{output}"
    end
    
    private def banner
      <<-BANNER
      
    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █░░░░░░░░░░ S T E G O H I D E ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░█
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                     bad-antics v#{VERSION}

  Advanced Steganography Tool - PNG/WAV LSB Encoding with AES-256
  
  USAGE:
    stegohide -m encode -i secret.txt -c cover.png -o output.png [-k password]
    stegohide -m decode -i output.png -o secret.txt [-k password]
  
  OPTIONS:
      BANNER
    end
  end
end

NullSec::CLI.new.run

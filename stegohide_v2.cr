# NullSec Stealth - Hardened Steganography & Data Exfiltration Tool
# Language: Crystal (Type-Safe, Fast)
# Author: bad-antics
# License: NullSec Proprietary
# Security Level: Maximum Hardening
#
# Security Features:
# - Compile-time type safety
# - Input validation on all operations
# - Secure memory handling with explicit zeroing
# - Constant-time operations for crypto
# - Defense-in-depth architecture
# - Comprehensive error handling

require "openssl"
require "digest"
require "option_parser"

module NullSec
  VERSION = "2.0.0"

  BANNER = <<-BANNER
  ██████  ▄▄▄█████▓▓█████   ▄████  ▒█████   ██░ ██  ██▓▓█████▄ ▓█████ 
▒██    ▒  ▓  ██▒ ▓▒▓█   ▀  ██▒ ▀█▒▒██▒  ██▒▓██░ ██▒▓██▒▒██▀ ██▌▓█   ▀ 
░ ▓██▄    ▒ ▓██░ ▒░▒███   ▒██░▄▄▄░▒██░  ██▒▒██▀▀██░▒██▒░██   █▌▒███   
  ▒   ██▒ ░ ▓██▓ ░ ▒▓█  ▄ ░▓█  ██▓▒██   ██░░▓█ ░██ ░██░░▓█▄   ▌▒▓█  ▄ 
▒██████▒▒   ▒██▒ ░ ░▒████▒░▒▓███▀▒░ ████▓▒░░▓█▒░██▓░██░░▒████▓ ░▒████▒
▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                    bad-antics • v#{VERSION}
  BANNER

  # ==========================================================================
  # Secure Memory Management
  # ==========================================================================
  
  module SecureMemory
    # Securely zero memory
    def self.zero(data : Bytes) : Nil
      data.each_index do |i|
        data[i] = 0_u8
      end
      # Memory barrier
      Atomic::Flag.new.test_and_set
    end
    
    # Create zeroing wrapper
    struct SecureBuffer
      getter size : Int32
      @data : Bytes
      @zeroed : Bool = false
      
      def initialize(@size)
        @data = Bytes.new(@size)
      end
      
      def initialize(data : Bytes)
        @size = data.size
        @data = data.dup
      end
      
      def as_bytes : Bytes
        raise "Buffer already zeroed" if @zeroed
        @data
      end
      
      def finalize
        unless @zeroed
          SecureMemory.zero(@data)
          @zeroed = true
        end
      end
      
      def explicit_zero! : Nil
        SecureMemory.zero(@data)
        @zeroed = true
      end
    end
  end

  # ==========================================================================
  # Input Validation
  # ==========================================================================
  
  module Validation
    MAX_FILE_SIZE  = 100_000_000 # 100MB
    MAX_KEY_LENGTH = 1024
    MIN_KEY_LENGTH = 8
    VALID_MODES    = {"encode", "decode", "analyze", "benchmark"}
    
    class ValidationError < Exception
    end
    
    def self.validate_file_path(path : String) : String
      raise ValidationError.new("Path too long") if path.size > 4096
      raise ValidationError.new("Path traversal detected") if path.includes?("..")
      raise ValidationError.new("Null byte in path") if path.includes?('\0')
      
      # Resolve to absolute path
      abs_path = File.expand_path(path)
      
      # Check existence
      unless File.exists?(abs_path)
        raise ValidationError.new("File not found: #{abs_path}")
      end
      
      # Check size
      size = File.size(abs_path)
      if size > MAX_FILE_SIZE
        raise ValidationError.new("File too large: #{size} bytes (max: #{MAX_FILE_SIZE})")
      end
      
      abs_path
    end
    
    def self.validate_output_path(path : String) : String
      raise ValidationError.new("Path too long") if path.size > 4096
      raise ValidationError.new("Path traversal detected") if path.includes?("..")
      raise ValidationError.new("Null byte in path") if path.includes?('\0')
      
      # Ensure parent directory exists
      parent = File.dirname(path)
      unless Dir.exists?(parent)
        raise ValidationError.new("Parent directory does not exist: #{parent}")
      end
      
      File.expand_path(path)
    end
    
    def self.validate_key(key : String) : String
      if key.size < MIN_KEY_LENGTH
        raise ValidationError.new("Key too short: minimum #{MIN_KEY_LENGTH} characters")
      end
      if key.size > MAX_KEY_LENGTH
        raise ValidationError.new("Key too long: maximum #{MAX_KEY_LENGTH} characters")
      end
      key
    end
    
    def self.validate_mode(mode : String) : String
      unless VALID_MODES.includes?(mode)
        raise ValidationError.new("Invalid mode: #{mode}. Valid: #{VALID_MODES.join(", ")}")
      end
      mode
    end
    
    def self.validate_bits(bits : Int32) : Int32
      unless bits >= 1 && bits <= 8
        raise ValidationError.new("Bits must be 1-8, got: #{bits}")
      end
      bits
    end
  end

  # ==========================================================================
  # Cryptographic Operations
  # ==========================================================================
  
  module Crypto
    KDF_ITERATIONS = 100_000
    SALT_SIZE      = 32
    KEY_SIZE       = 32
    IV_SIZE        = 12
    TAG_SIZE       = 16
    
    # Constant-time comparison to prevent timing attacks
    def self.constant_time_compare(a : Bytes, b : Bytes) : Bool
      return false unless a.size == b.size
      
      result = 0_u8
      a.size.times do |i|
        result |= a[i] ^ b[i]
      end
      result == 0
    end
    
    # Derive key from password using PBKDF2
    def self.derive_key(password : String, salt : Bytes? = nil) : {Bytes, Bytes}
      # Generate or use provided salt
      actual_salt = salt || Random::Secure.random_bytes(SALT_SIZE)
      
      # PBKDF2 key derivation
      key = OpenSSL::PKCS5.pbkdf2_hmac(
        password,
        actual_salt,
        iterations: KDF_ITERATIONS,
        algorithm: OpenSSL::Algorithm::SHA256,
        key_size: KEY_SIZE
      )
      
      {key, actual_salt}
    end
    
    # AES-256-GCM Encryption
    def self.encrypt(plaintext : Bytes, password : String) : Bytes
      # Derive key
      key, salt = derive_key(password)
      key_buffer = SecureMemory::SecureBuffer.new(key)
      
      # Generate random IV
      iv = Random::Secure.random_bytes(IV_SIZE)
      
      # Create cipher
      cipher = OpenSSL::Cipher.new("aes-256-gcm")
      cipher.encrypt
      cipher.key = key_buffer.as_bytes
      cipher.iv = iv
      
      # Encrypt
      ciphertext = cipher.update(plaintext)
      ciphertext += cipher.final
      
      # Get auth tag
      tag = cipher.auth_tag(TAG_SIZE)
      
      # Clear key from memory
      key_buffer.explicit_zero!
      
      # Format: salt || iv || tag || ciphertext
      result = Bytes.new(salt.size + iv.size + tag.size + ciphertext.size)
      result.copy_from(salt, salt.size, 0)
      result.copy_from(iv, iv.size, salt.size)
      result.copy_from(tag, tag.size, salt.size + iv.size)
      ciphertext.each_with_index { |b, i| result[salt.size + iv.size + tag.size + i] = b }
      
      result
    end
    
    # AES-256-GCM Decryption
    def self.decrypt(ciphertext : Bytes, password : String) : Bytes?
      min_size = SALT_SIZE + IV_SIZE + TAG_SIZE
      return nil if ciphertext.size < min_size
      
      # Extract components
      salt = ciphertext[0, SALT_SIZE]
      iv = ciphertext[SALT_SIZE, IV_SIZE]
      tag = ciphertext[SALT_SIZE + IV_SIZE, TAG_SIZE]
      encrypted = ciphertext[(min_size)..]
      
      # Derive key
      key, _ = derive_key(password, salt)
      key_buffer = SecureMemory::SecureBuffer.new(key)
      
      begin
        # Create cipher
        cipher = OpenSSL::Cipher.new("aes-256-gcm")
        cipher.decrypt
        cipher.key = key_buffer.as_bytes
        cipher.iv = iv
        cipher.auth_tag = tag
        
        # Decrypt
        plaintext = cipher.update(encrypted)
        plaintext += cipher.final
        
        key_buffer.explicit_zero!
        plaintext
      rescue
        key_buffer.explicit_zero!
        nil
      end
    end
    
    # Compute checksum for integrity
    def self.checksum(data : Bytes) : Bytes
      Digest::SHA256.digest(data)
    end
  end

  # ==========================================================================
  # PNG Steganography Engine
  # ==========================================================================
  
  class PNGSteganography
    MAGIC = Bytes[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
    HEADER_SIZE = 8
    
    struct Chunk
      property type : String
      property data : Bytes
      property crc : UInt32
      
      def initialize(@type, @data, @crc)
      end
    end
    
    @chunks : Array(Chunk) = [] of Chunk
    @width : UInt32 = 0
    @height : UInt32 = 0
    @bit_depth : UInt8 = 0
    @color_type : UInt8 = 0
    
    def initialize(path : String)
      @path = Validation.validate_file_path(path)
      parse_png
    end
    
    # Calculate maximum embeddable capacity
    def capacity(bits_per_channel : Int32 = 1) : Int64
      pixels = @width.to_i64 * @height.to_i64
      channels = case @color_type
                 when 0 then 1 # Grayscale
                 when 2 then 3 # RGB
                 when 3 then 1 # Palette
                 when 4 then 2 # Grayscale + Alpha
                 when 6 then 4 # RGBA
                 else        3
                 end
      (pixels * channels * bits_per_channel) / 8
    end
    
    private def parse_png
      File.open(@path, "rb") do |file|
        # Verify magic
        magic = Bytes.new(HEADER_SIZE)
        file.read(magic)
        
        unless Crypto.constant_time_compare(magic, MAGIC)
          raise Validation::ValidationError.new("Invalid PNG magic bytes")
        end
        
        # Parse chunks
        while !file.pos >= file.size
          # Read chunk length (4 bytes, big-endian)
          length_bytes = Bytes.new(4)
          break if file.read(length_bytes) < 4
          length = IO::ByteFormat::BigEndian.decode(UInt32, length_bytes)
          
          # Sanity check
          if length > 0x7FFFFFFF
            raise Validation::ValidationError.new("Chunk length too large")
          end
          
          # Read chunk type
          type_bytes = Bytes.new(4)
          file.read(type_bytes)
          type = String.new(type_bytes)
          
          # Read chunk data
          data = Bytes.new(length)
          file.read(data) if length > 0
          
          # Read CRC
          crc_bytes = Bytes.new(4)
          file.read(crc_bytes)
          crc = IO::ByteFormat::BigEndian.decode(UInt32, crc_bytes)
          
          @chunks << Chunk.new(type, data, crc)
          
          # Parse IHDR
          if type == "IHDR" && data.size >= 13
            @width = IO::ByteFormat::BigEndian.decode(UInt32, data[0, 4])
            @height = IO::ByteFormat::BigEndian.decode(UInt32, data[4, 4])
            @bit_depth = data[8]
            @color_type = data[9]
          end
          
          break if type == "IEND"
        end
      end
    end
    
    def info : String
      String.build do |str|
        str << "PNG Information:\n"
        str << "  Path:       #{@path}\n"
        str << "  Dimensions: #{@width}x#{@height}\n"
        str << "  Bit Depth:  #{@bit_depth}\n"
        str << "  Color Type: #{@color_type}\n"
        str << "  Chunks:     #{@chunks.size}\n"
        str << "  Capacity:   ~#{capacity} bytes (1-bit LSB)\n"
      end
    end
  end

  # ==========================================================================
  # LSB Steganography Engine
  # ==========================================================================
  
  class LSBEngine
    SIGNATURE = "NSEC".to_slice
    VERSION_BYTE = 0x02_u8
    
    struct Header
      property version : UInt8
      property flags : UInt8
      property length : UInt32
      property checksum : Bytes
      
      def initialize(@version, @flags, @length, @checksum)
      end
      
      def to_bytes : Bytes
        result = Bytes.new(40) # 1 + 1 + 4 + 2 + 32 = 40
        result[0] = @version
        result[1] = @flags
        IO::ByteFormat::LittleEndian.encode(@length, result + 2)
        result[6] = 0_u8  # Reserved
        result[7] = 0_u8  # Reserved
        @checksum.copy_to(result + 8, 32)
        result
      end
      
      def self.from_bytes(data : Bytes) : Header
        raise Validation::ValidationError.new("Header too short") if data.size < 40
        
        version = data[0]
        flags = data[1]
        length = IO::ByteFormat::LittleEndian.decode(UInt32, data[2, 4])
        checksum = data[8, 32].dup
        
        Header.new(version, flags, length, checksum)
      end
    end
    
    @bits_per_channel : Int32
    
    def initialize(@bits_per_channel : Int32 = 1)
      @bits_per_channel = Validation.validate_bits(@bits_per_channel)
    end
    
    # Embed data into carrier bytes
    def embed(carrier : Bytes, payload : Bytes) : Bytes
      # Calculate space needed
      header_size = SIGNATURE.size + 40  # sig + header
      total_size = header_size + payload.size
      bits_needed = total_size * 8 / @bits_per_channel
      
      if bits_needed > carrier.size
        raise Validation::ValidationError.new(
          "Carrier too small: need #{bits_needed} bytes, have #{carrier.size}"
        )
      end
      
      # Create header
      checksum = Crypto.checksum(payload)
      header = Header.new(VERSION_BYTE, 0_u8, payload.size.to_u32, checksum)
      
      # Combine signature + header + payload
      embed_data = Bytes.new(total_size)
      SIGNATURE.copy_to(embed_data)
      header.to_bytes.copy_to(embed_data + SIGNATURE.size)
      payload.copy_to(embed_data + header_size)
      
      # Embed using LSB
      result = carrier.dup
      embed_bits(result, embed_data)
      
      result
    end
    
    # Extract data from carrier
    def extract(carrier : Bytes) : Bytes?
      # Check minimum size
      min_bits = (SIGNATURE.size + 40) * 8 / @bits_per_channel
      return nil if carrier.size < min_bits
      
      # Extract signature
      sig_data = extract_bytes(carrier, 0, SIGNATURE.size)
      unless Crypto.constant_time_compare(sig_data, SIGNATURE)
        return nil # No signature found
      end
      
      # Extract header
      header_data = extract_bytes(carrier, SIGNATURE.size, 40)
      header = Header.from_bytes(header_data)
      
      # Validate version
      return nil if header.version != VERSION_BYTE
      
      # Validate length
      max_length = (carrier.size * @bits_per_channel / 8) - SIGNATURE.size - 40
      return nil if header.length > max_length
      
      # Extract payload
      offset = SIGNATURE.size + 40
      payload = extract_bytes(carrier, offset, header.length.to_i32)
      
      # Verify checksum
      computed_checksum = Crypto.checksum(payload)
      unless Crypto.constant_time_compare(computed_checksum, header.checksum)
        return nil # Checksum mismatch
      end
      
      payload
    end
    
    private def embed_bits(carrier : Bytes, data : Bytes)
      mask = (1 << @bits_per_channel) - 1
      clear_mask = (0xFF ^ mask).to_u8
      
      bit_index = 0
      data.each do |byte|
        8.times do |bit_pos|
          break if bit_index >= carrier.size
          
          bit_value = (byte >> (7 - bit_pos)) & 1
          channel_value = carrier[bit_index]
          
          # Clear LSBs and set new value
          new_value = (channel_value & clear_mask) | (bit_value.to_u8 << (@bits_per_channel - 1 - (bit_index % @bits_per_channel)))
          carrier[bit_index] = new_value
          
          bit_index += 1 if (bit_pos + 1) % @bits_per_channel == 0 || @bits_per_channel == 1
        end
      end
    end
    
    private def extract_bytes(carrier : Bytes, offset : Int32, length : Int32) : Bytes
      result = Bytes.new(length)
      bit_offset = offset * 8 / @bits_per_channel
      
      length.times do |i|
        byte = 0_u8
        8.times do |bit_pos|
          byte_index = bit_offset + (i * 8 + bit_pos) / @bits_per_channel
          break if byte_index >= carrier.size
          
          bit_value = (carrier[byte_index] >> (@bits_per_channel - 1)) & 1
          byte = (byte << 1) | bit_value
        end
        result[i] = byte
      end
      
      result
    end
  end

  # ==========================================================================
  # Command Line Interface
  # ==========================================================================
  
  class CLI
    @mode : String = "encode"
    @input_file : String = ""
    @output_file : String = ""
    @payload_file : String = ""
    @password : String = ""
    @bits : Int32 = 1
    @verbose : Bool = false
    
    def run
      parse_args
      
      case @mode
      when "encode"
        encode_operation
      when "decode"
        decode_operation
      when "analyze"
        analyze_operation
      when "benchmark"
        benchmark_operation
      end
    rescue ex : Validation::ValidationError
      STDERR.puts "[!] Validation Error: #{ex.message}"
      exit(1)
    rescue ex
      STDERR.puts "[!] Error: #{ex.message}"
      exit(1)
    end
    
    private def parse_args
      OptionParser.parse do |parser|
        parser.banner = BANNER + "\n\nUsage: stegohide [options]"
        
        parser.on("-m MODE", "--mode=MODE", "Mode: encode, decode, analyze, benchmark") do |m|
          @mode = Validation.validate_mode(m)
        end
        
        parser.on("-i FILE", "--input=FILE", "Input carrier file") do |f|
          @input_file = f
        end
        
        parser.on("-o FILE", "--output=FILE", "Output file") do |f|
          @output_file = f
        end
        
        parser.on("-p FILE", "--payload=FILE", "Payload file to embed") do |f|
          @payload_file = f
        end
        
        parser.on("-k KEY", "--key=KEY", "Encryption password") do |k|
          @password = k
        end
        
        parser.on("-b BITS", "--bits=BITS", "Bits per channel (1-8)") do |b|
          @bits = Validation.validate_bits(b.to_i)
        end
        
        parser.on("-v", "--verbose", "Verbose output") do
          @verbose = true
        end
        
        parser.on("-h", "--help", "Show help") do
          puts parser
          exit(0)
        end
      end
    end
    
    private def encode_operation
      validate_required_args(["input", "output", "payload", "key"])
      
      puts "[*] Encoding Operation"
      puts "    Input:   #{@input_file}"
      puts "    Output:  #{@output_file}"
      puts "    Payload: #{@payload_file}"
      
      # Load carrier
      input_path = Validation.validate_file_path(@input_file)
      carrier = File.read(input_path).to_slice
      
      # Load payload
      payload_path = Validation.validate_file_path(@payload_file)
      payload = File.read(payload_path).to_slice
      
      puts "[*] Payload size: #{payload.size} bytes"
      
      # Encrypt payload
      encrypted = Crypto.encrypt(payload, Validation.validate_key(@password))
      puts "[*] Encrypted size: #{encrypted.size} bytes"
      
      # Embed
      engine = LSBEngine.new(@bits)
      result = engine.embed(carrier, encrypted)
      
      # Write output
      output_path = Validation.validate_output_path(@output_file)
      File.write(output_path, result)
      
      puts "[+] Successfully encoded to #{output_path}"
    end
    
    private def decode_operation
      validate_required_args(["input", "key"])
      
      puts "[*] Decoding Operation"
      puts "    Input: #{@input_file}"
      
      # Load carrier
      input_path = Validation.validate_file_path(@input_file)
      carrier = File.read(input_path).to_slice
      
      # Extract
      engine = LSBEngine.new(@bits)
      encrypted = engine.extract(carrier)
      
      if encrypted.nil?
        puts "[!] No hidden data found"
        exit(1)
      end
      
      puts "[*] Extracted #{encrypted.size} bytes"
      
      # Decrypt
      decrypted = Crypto.decrypt(encrypted, Validation.validate_key(@password))
      
      if decrypted.nil?
        puts "[!] Decryption failed - wrong password or corrupted data"
        exit(1)
      end
      
      puts "[+] Decrypted #{decrypted.size} bytes"
      
      if @output_file.empty?
        puts "\n--- BEGIN PAYLOAD ---"
        puts String.new(decrypted)
        puts "--- END PAYLOAD ---"
      else
        output_path = Validation.validate_output_path(@output_file)
        File.write(output_path, decrypted)
        puts "[+] Written to #{output_path}"
      end
    end
    
    private def analyze_operation
      validate_required_args(["input"])
      
      puts "[*] Analyzing: #{@input_file}"
      
      input_path = Validation.validate_file_path(@input_file)
      
      # Check if PNG
      if input_path.ends_with?(".png")
        png = PNGSteganography.new(input_path)
        puts png.info
      else
        data = File.read(input_path).to_slice
        puts "  File Size:  #{data.size} bytes"
        puts "  Capacity:   ~#{data.size / 8} bytes (1-bit LSB)"
        
        # Try to detect hidden data
        engine = LSBEngine.new(@bits)
        if engine.extract(data)
          puts "  \033[32m[!] Hidden data detected!\033[0m"
        else
          puts "  No hidden data detected"
        end
      end
    end
    
    private def benchmark_operation
      puts "[*] Running Benchmark"
      
      # Benchmark encryption
      test_data = Random::Secure.random_bytes(1024 * 1024) # 1MB
      password = "benchmark_password_12345"
      
      puts "    Encrypting 1MB..."
      t1 = Time.monotonic
      encrypted = Crypto.encrypt(test_data, password)
      t2 = Time.monotonic
      
      enc_time = (t2 - t1).total_milliseconds
      puts "    Encryption: #{enc_time.round(2)}ms (#{(1000.0 / enc_time).round(2)} MB/s)"
      
      puts "    Decrypting..."
      t3 = Time.monotonic
      Crypto.decrypt(encrypted, password)
      t4 = Time.monotonic
      
      dec_time = (t4 - t3).total_milliseconds
      puts "    Decryption: #{dec_time.round(2)}ms (#{(1000.0 / dec_time).round(2)} MB/s)"
    end
    
    private def validate_required_args(required : Array(String))
      required.each do |arg|
        case arg
        when "input"
          if @input_file.empty?
            raise Validation::ValidationError.new("Input file required (-i)")
          end
        when "output"
          if @output_file.empty?
            raise Validation::ValidationError.new("Output file required (-o)")
          end
        when "payload"
          if @payload_file.empty?
            raise Validation::ValidationError.new("Payload file required (-p)")
          end
        when "key"
          if @password.empty?
            raise Validation::ValidationError.new("Password required (-k)")
          end
        end
      end
    end
  end
end

# Entry point
NullSec::CLI.new.run

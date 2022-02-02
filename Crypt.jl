module Crypt

export encrypt, decrypt, generate_key, pack, unpack, generate_e, bezout, fmod, generate_primes, prime_check_fermat, generate_random

function encrypt(message, public_key, block_size, DEBUG=false)
  DEBUG && println(message)
  M = pack(message, block_size, DEBUG)
  DEBUG && println(M)
  len = length(M)
  R = zeros(BigInt, len)
  for i in 1:len
    R[i] = powermod(M[i], (public_key[1]), public_key[2])
  end
  DEBUG && println(R)
  return R
end

function decrypt(R, private_key, block_size, DEBUG=false)
  M = Vector{BigInt}()
  for i in R
    push!(M, powermod(i, (private_key[1]), private_key[2]))
  end
  message = unpack(M, block_size, DEBUG)
  DEBUG && println("DECRYPTED VALUES: $M")
  return message
end

function generate_key(bits::BigInt, confidence, DEBUG=false)
  DEBUG && println("Generating key...")
  p = generate_primes(bits+4,confidence, DEBUG)
  q = generate_primes(bits,confidence, DEBUG)
  println("p = $p\nq = $q")
  e = generate_e(p, q, DEBUG)
  DEBUG && println(e)
  ϕ = (p-1)*(q-1)
  ret = bezout(ϕ, e, DEBUG)
  d = ret[2] % ((p-1)*(q-1))
  d = d<0 ? d+(p-1)*(q-1) : d
  DEBUG && println("Generated keys")
  n = p*q
  return ((e,n), (d,n))
end

function pack(message, block_size, DEBUG=false)
  if length(message) % block_size != 0
    spaces = ' '^(block_size - length(message)%block_size)
    message = message*spaces
  end
  iterations = BigInt(length(message)÷block_size)
  ret = zeros(BigInt, iterations)
  for i in 1:iterations
    M::BigInt = 0 
    group = message[(i-1)*block_size+1:i*block_size]
    for x in group
      M = M<<8 | Int(x)
    end
    ret[i] = M
    DEBUG && println("M = $M")
  end
  DEBUG && println("Packing...")
  DEBUG && println("Packed")
  return ret
end

function unpack(M::Vector{BigInt}, block_size, DEBUG=false)
  message = ""
  for x in M
    group = ""
    for i in 1:block_size
      y = x &  0xff
      group = Char(y)*group
      x = x>>8
    end
    message = message*group
  end
  return message
end

function generate_e(p::BigInt,q::BigInt, DEBUG=false)
  x = rand()
  y = BigInt(floor(x*((p-1)*(q-1)-2))) + 2
  while gcd(y, (p-1)*(q-1)) != 1
    y += 1
  end
  return y
end

function bezout(a::BigInt, b::BigInt, DEBUG=false)
  x = Matrix{BigInt}(undef, 2, 3)
  x[1,:] = [a 1 0]
  x[2,:] = [b 0 1]
  i = 1
  while x[i+1,1] != 0
    rem = x[i,1]%x[i+1,1]
    q = x[i,1]÷x[i+1,1]
    n1 = x[i,2] - q*x[i+1,2]
    n2 = x[i,3] - q*x[i+1,3]
    x = vcat(x, [rem n1 n2])
    i += 1
  end
  DEBUG && display(x)
  return x[i,2], x[i,3]
end

function fmod(a::BigInt, b::BigInt, n::BigInt, DEBUG=false)
  t = b
  pow = 0
  res = 1
  while t != 0
    t = t>>1
    pow += 1
  end
  mods = zeros(BigInt,pow)
  pow -= 1
  t = b
  mods[1] = a%n
  for i in 1:pow
    mods[i+1] = (mods[i]^2) % n
  end
  for i in 1:pow+1
    res = t&1 == 1 ? res*mods[i] : res
    t = t>>1
  end
  return res%n
end

function generate_primes(bits::BigInt, confidence, DEBUG=false)
  DEBUG && println("Generating primes...")
  num = generate_random(bits)
  DEBUG && println("Random odd number chosen")
  found = false
  while found == false
    num += 2
    found = prime_check_low(num, DEBUG) && prime_check_fermat(num, confidence, DEBUG)
    DEBUG && println("Checking $num...")
  end
  return num
end

function generate_random(bits::BigInt)
  range = 2^(bits-1):2^(bits)
  num = rand(range)
  num = num%2 == 0 ? num + 1 : num
  return num
end

function prime_check_fermat(num, confidence, DEBUG=false)
  i = 1
  prime = true
  while i <= confidence && prime == true 
    a = rand(2:num-1)
    rem = powermod(a, num-1, num)
    prime = rem == 1 ? true : false
    i += 1
  end
  return prime
end

function prime_check_low(num, DEBUG=false)
  prime = true
  low_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349]
  for x in low_primes
    if num%x == 0
      prime = false
      break
    end
  end
  return prime
end

end

push!(LOAD_PATH, pwd())
using Crypt
using Base64

#function generate(args, vars, settings, DEBUG)
#  @time (public_key, private_key) = generate_key(parse(BigInt,args[1]), parse(Int, args[2])) 
#  push!(vars, "private key"=>private_key)
#  push!(vars, "public key"=>public_key)
#  println(public_key)
#  fp1 = open(settings["path"]["private key"], "w")
#  fp2 = open(settings["path"]["public key"], "w")
#  write(fp1, string(vars["private key"][1]), ", ", string(vars["private key"][2]))
#  write(fp2, string(vars["public key"][1]), ", ", string(vars["public key"][2]))
#  close(fp1)
#  close(fp2)
#  println("We have updated the private key to $(settings["path"]["private key"]) and the public key to $(settings["path"]["public key"])")
#end
#
##function usekey(args, vars, DEBUG)
##  push!(vars, "reciever key"=>(parse(BigInt,args[1]), parse(BigInt,args[2])))
##end
#
#function Encrypt(args, vars, settings, DEBUG)
#    fp = open(settings["path"]["cipher text"], "w")
#    t = split(filter(!isempty, readlines(settings["path"]["receiver key"]))[1], ',')
#    rec_key = map(x->parse(BigInt, x), t)
#    receiver_key = (rec_key[1], rec_key[2])
#    push!(vars, "receiver key"=>receiver_key)
#    @time cipher = Crypt.encrypt(args[1], vars["receiver key"], parse(Int64,args[2]))
#    DEBUG && println(cipher)
#    t = unpack_cipher.(cipher)
#    cipher_text = join(t, ' ')
#    push!(vars, "message"=>args[1])
#    push!(vars, "cipher text"=>cipher_text)
#    printstyled("$cipher_text\n", color = :yellow)
#    write(fp, cipher_text, "\n", args[2])
#    close(fp)
#    println("We have updated the encrypted message to $(settings["path"]["cipher text"])")
#end

function Decrypt(args, vars, settings, DEBUG=false)
  t = split(filter(!isempty, readlines(settings["path"]["private key"]))[1], ',')
  priv_key = map(x->parse(BigInt, x), t)
  private_key = (priv_key[1], priv_key[2])
  push!(vars, "private key"=>private_key)
  t = split(filter(!isempty, readlines(settings["path"]["public key"]))[1], ',')
  pub_key = map(x->parse(BigInt, x), t)
  public_key = (pub_key[1], pub_key[2])
  push!(vars, "public key"=>public_key)
  input = filter(!isempty, readlines(settings["path"]["cipher text"]))
  cipher_text = input[1]
  DEBUG && println("Length of args: $(length(args))")
  t = filter(!isempty,split(cipher_text, ' '))
  cipher = pack_cipher.(t)
  DEBUG && println(cipher)
  @time message = decrypt(cipher, vars["private key"], parse(Int64, input[2]))
  printstyled("$message\n", color = :yellow)
  push!(vars, "message"=>message)
end

#function status(args, vars, settings, DEBUG)
#  for x in vars
#    printstyled("$(x[1])", color = :blue)
#    print(" : ")
#    printstyled("$(x[2])\n", color = :green)
#  end
#end

function unpack_cipher(x::BigInt, DEBUG=false)
  group = Vector{UInt8}()
  while x != 0
    y = x & 0xff
    push!(group, y)
    x = x>>8
  end
  return base64encode(reverse(group))
end

function pack_cipher(message, DEBUG=false)
  x::BigInt = 0
  a = base64decode(message)
  x = a[1]
  for i in 2:length(a)
    x = x<<8
    x = x | a[i]
  end
  return x
end

#function unpack_cipher(x::BigInt, DEBUG=false)
#  y = string(x)
#  return base64encode(y)
#end
#
#function pack_cipher(message, DEBUG=false)
#  x = base64decode(message)
#  y = map(a->Char(a), x)
#  z = foldl(*, y)
#  return parse(BigInt,z)
#end

#function debug(args, vars, settings, DEBUG)
#  push!(vars, "debug"=>!(vars["debug"]))
#  println("debug set to $(vars["debug"]).")
#end
#
#function pushkey(args, vars, DEBUG)
#  push!(vars, "private key"=>(parse(BigInt, args[1]), parse(BigInt, args[2])))
#end
#
#function exit(args, vars, settings, DEBUG)
#  Base.exit()
#end

function init_settings(input)
  settings = Dict{String, Any}()
  current_dict = settings
  prev_dict = Dict{String, Any}()
  for x in input
    new_dict = Dict{String, Any}()
    y = split(x)
    y = map(z->replace(z, r"(^ *)|( *$)"=>""), y)
    if y[1] == "set"
      push!(current_dict, split(x)[2]=>new_dict)
      prev_dict = current_dict
      current_dict = new_dict
    elseif y[1] == "end"
      current_dict = prev_dict
    else
      x = split(x, '=')
      x = map(z->replace(z, r"(^ *)|( *$)"=>""), x)
      push!(current_dict, x[1]=>x[2])
    end
  end
  return settings
end


function primitive_factorize(n)
  factors = []
  while n%2 == 0
    n = n/2
    push!(factors, 2)
  end
  for i in 3:2:BigInt(floor(sqrt(n)))
    while n%i == 0
      push!(factors, i)
      n = n/i
    end
  end
  if n != 1
    push!(factors, BigInt(n))
  end
  return factors
end

function fermat_factorize(n)
  factors = []
  while n%2 == 0
    n = n/2
    push!(factors, 2)
  end
  k = BigInt(floor(sqrt(n))) + 1
  d = k^2 - n
  i = 1
  while sqrt(d) != floor(sqrt(d))
    d = (k+i)^2 - n
    i += 1
  end
  d1 = BigInt(sqrt(d))
  factors = [k+i-1+d1, k+i-1-d1]
end

settings = init_settings(filter(!isempty,readlines("config.act")))
t = split(filter(!isempty, readlines(settings["path"]["receiver key"]))[1], ',')
receiver_key = map(x->parse(BigInt, x), t)
println("Rec Key: $receiver_key")
@time factors = fermat_factorize(receiver_key[2])
(p,q) = factors[1:2]
println("$(receiver_key[2]) = $p × $q")
ret  = bezout((p-1)*(q-1), receiver_key[1])
d = ret[2] % ((p-1)*(q-1))
d = d<0 ? d+(p-1)*(q-1) : d
receiver_private_key = (d, receiver_key[2])
println("Private key: $receiver_private_key")

input = filter(!isempty, readlines(settings["path"]["cipher text"]))
cipher_text = input[1]
#DEBUG && println("Length of args: $(length(args))")
t = filter(!isempty,split(cipher_text, ' '))
cipher = pack_cipher.(t)
#DEBUG && println(cipher)
@time message = decrypt(cipher, receiver_private_key, parse(Int64, input[2]))
printstyled("$message\n", color = :yellow)

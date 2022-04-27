local M = {
	_key_bindings={}
}

M.on_eof = function() end

M.on_key = function(key)
	local prevent_default = false
	for fn in pairs(M._key_bindings[key] or {}) do
		fn()
		prevent_default = true
	end
	return prevent_default
end

function M.add_key_binding(key, fn)
	M._key_bindings[key] = M._key_bindings[key] or {}
	M._key_bindings[key][fn] = true
end

return M

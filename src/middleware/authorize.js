export function authorize (...roles) {
  return function authorizeMiddleware (req, res, next) {
      // Lista extendida de roles permitidos
      const validRoles = [
        'worker',
        'supervisor',
        'manager',
        'district_manager',
        'jefe_operaciones',
        'senior_jefe_operaciones',
        'vicepresidente_zonal',
        'presidente_zonal',
        'ceo'
      ];
      if (!req.user || !validRoles.includes(req.user.role) || !roles.includes(req.user.role)) {
        return res.status(403).json({ success: false, message: 'Acceso denegado: rol insuficiente.' });
      }
      return next();
  };
}

export default authorize;

#include <math.h>
#include <float.h>

// Return the cubic root of the parameter a in a relative precision DBL_EPSILON
double CubicRoot(double a)
{
	long double x1, x2, d;
	// in case the initial guess is too small to be safe
	// the initial guess is made easy to calculate
	if(a >= 0)
		x1 = (a + 1) / 2;
	else
		x1 = (a - 1) / 2;

	// The Newton-Raphson Method to approximate the root
	do
	{
		x2 = (2 * x1 + a / x1 / x1) / 3;
		d = (x2 - x1);
		x1 = x2;
	} while(fabs(d / x2) > DBL_EPSILON);
	//
	return (double)x2;
}

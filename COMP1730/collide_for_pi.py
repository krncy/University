"""
This module implements a simulation of 1D particle collisions to approximate the value of pi using Grigorii Galperin's block colliding algorithm. This algorithm uses 2 blocks with a fixed mass ratio colliding with a wall.

Classes:

Particle: A class representing a particle in 1D space with mass, width, position and velocity attributes.
Particles: A class representing a collection of particles.

Functions:

main(): The main function that accepts command-line arguments to set the value of N and the display flag. It then calculates the number of collisions required to approximate pi and prints the result.

calculate_collision(N, display=False): A function that calculates the number of collisions required to approximate pi given the mass ratio N and the display flag. It returns the number of collisions required.

Attributes:

-n N:   The degree (N, a non-negative integer) to which pi will be approximated.
-d:     A flag that if set, displays a visual simulation of the collisions.
-t:     A flag that if set, executes the testing suite.

Usage:

To run the simulation, call the main() function with command-line arguments -n N, -d, -t. The default value of N is 1 if not specified.

# YOUR ANU ID: u6668002
# YOUR NAME: Thomas Krnc
"""

import math
import signal
import sys

import matplotlib.pyplot as plt
import matplotlib.animation as animation
import matplotlib.patches as patches

class Particle:
    """
    A class representing a particle in 1D space.

    Attributes:
    - mass (float): the mass of the particle
    - width (float): the width of the particle
    - position (float): the position of the particle in space
    - velocity (float): the velocity of the particle in space
    """

    def __init__(self, mass, width, position, velocity):
        """
        Initializes a new Particle object.

        Parameters:
        - mass (float): the mass of the particle
        - width (float): the width of the particle
        - position (float): the position of the particle in space
        - velocity (float): the velocity of the particle in space
        """
        self.mass = mass
        self.width = width
        self.position = position
        self.velocity = velocity

    def update_after_time(self, time):
        """
        Updates the position of the particle after a given time has passed.

        Parameters:
        - time (float): the amount of time that has passed since the last update

        Returns:
        None
        """
        assert type(time) == float or type(time) == int
        assert time >= 0
        
        self.position = self.position + self.velocity * time

    def deep_copy(self):
        """
        Creates a deep copy of the Particle object.

        Parameters:
        None

        Returns:
        A new Particle object with the same mass, width, position, and velocity as the original.
        """
        return Particle(self.mass, self.width, self.position, self.velocity)
    
    def __str__(self):
        return f"(Mass: {self.mass}, Width: {self.width}, Position: {self.position}, Velocity: {self.velocity})"

class Particles:
    """
    A class representing a collection of particles.

    Attributes:
    - particles (list of Particle objects): the particles in the collection
    """

    def __init__(self, particles=[]):
        """
        Initializes a new Particles object.

        Parameters:
        - particles (list of Particle objects): the particles to add to the collection, if any (default is an empty list)
        """
        
        # Ensure the list of particles is ordered by position.
        self.particles = sorted(particles, key = lambda x: x.position)
    
    def add_particle(self, particle):
        """
        Adds a particle to the collection, maintaining a sorted order by position.

        Parameters:
        - particle (Particle object): the particle to add to the collection

        Returns:
        None
        """
        # Flag to keep track if the particle has been added or not
        added_flag = False  
             
        for i in range(len(self.particles)):
            # If the position of the particle to be added is less than the position of the current particle in the collection,
            # insert the particle at that index to maintain the sorted order by position
            if particle.position < self.particles[i].position:
                self.particles.insert(i, particle)
                added_flag = True
                break
        
        # If the particle has not been added yet (because the collection is empty or it is the last particle)
        # append it to the end of the collection
        if not added_flag:
            self.particles.append(particle)
  
    def velocity_after_collision(self, p1_index, p2_index):
        """
        Calculates the new velocities of two particles after they collide using conservation of momentum and kinetic energy.
        Assumes fully elastic collisions.

        Args:
            p1_index (int): The index of the first particle in the collection.
            p2_index (int): The index of the second particle in the collection.

        Returns:
            tuple: A tuple containing the new velocity of each particle after the collision.
        """
        # Verify that the indices are valid.
        assert (0 <= p1_index < p2_index < len(self.particles))  

        # Get references to the two particles.
        p1 = self.particles[p1_index]
        p2 = self.particles[p2_index]
        
        # If both particles have infinite mass, they will not change velocities.
        if p1.mass == float("inf") and p2.mass == float("inf"):  
            v1 = p2.velocity
            v2 = p1.velocity
        
        # If p1 has infinite mass, it will not change velocity but p2 will rebound.
        elif p1.mass == float("inf"):  
            v1 = p1.velocity
            v2 = -p2.velocity + 2 * p1.velocity
        
        # If p2 has infinite mass, it will not change velocity but p1 will rebound.
        elif p2.mass == float("inf"):  
            v1 = -p1.velocity + 2 * p2.velocity
            v2 = p2.velocity
        
        # If both particles have finite mass, calculate the new velocities using conservation of momentum and kinetic energy.
        else:  
            a = p1.mass - p2.mass
            b = p1.mass + p2.mass

            v1 = (a * p1.velocity + 2 * p2.mass * p2.velocity) / b
            v2 = (-a * p2.velocity + 2 * p1.mass * p1.velocity) / b

        return (v1, v2)

    def time_to_collide(self, p1_index, p2_index):
        """
        Calculates the time until two particles collide.

        Parameters:
        - p1_index (int): the index of the first particle in the collection
        - p2_index (int): the index of the second particle in the collection

        Returns:
        The time until the particles collide, in seconds.
        If the particles are already colliding or moving away from each other, returns None.
        If both particles are moving with the same velocity, returns infinity.
        """
        # Verify that the indices are valid.
        assert (0 <= p1_index < p2_index < len(self.particles))
        
        # Get references to the two particles.
        p1 = self.particles[p1_index]
        p2 = self.particles[p2_index]
        
        # If both particles have the same velocity, they will never collide.
        if p1.velocity == p2.velocity:  
            return float("inf")

        # Calculate the time until the particles collide.
        t = (p1.position + p1.width - p2.position) / (p2.velocity - p1.velocity)
        
        # If the time is positive, the particles will collide.
        if t > 0:  
            return t
        # If the time is negative, the particles are already colliding or moving away from each other.
        else:  
            return None

    def update_particles_after_time(self, time):
        """
        Updates the state of each particle in the collection after a given time.

        Args:
            time (float): The amount of time that has passed.
        """
        
        assert type(time) == float or type(time) == int
        assert time >= 0
        
        for particle in self.particles:
            particle.update_after_time(time)

    def update_particle_velocity_after_collision(self, p1_index, p2_index):
        """
        Updates the velocities of two particles in the collection after a collision.

        Args:
            p1_index (int): The index of the first particle in the collection.
            p2_index (int): The index of the second particle in the collection.
        """
        self.particles[p1_index].velocity, self.particles[p2_index].velocity = self.velocity_after_collision(p1_index, p2_index)

    def deep_copy(self):
        """
        Creates a deep copy of the collection of particles.

        Returns:
            Particles: A new instance of the Particles class containing a deep copy of each particle in the original collection.
        """
        return Particles([i.deep_copy() for i in self.particles])
    
    def __str__(self):
        output = ""
        for particle in self.particles:
            output += str(particle) + "\n"
        return output
        
def main():
    
    # Default mass ratio
    N = 1
    
    # Flag for whether to display the animation of particles
    display = False
    
    i = 0
    
    # Loop through command-line arguments (-d, -t, -n for the display flag, testing flag, and the mass ratio respectivley)
    while i < len(sys.argv):
        if sys.argv[i] == '-d':
            display = True
            
        elif sys.argv[i] == '-t':
            testing()
            exit()
        
        elif sys.argv[i] == '-n':
            i += 1
            if i >= len(sys.argv):
                print("No -n value passed")
                exit()
            else:
                try:
                    N = int(sys.argv[i])
                    if N < 0:
                        raise ValueError()
                except ValueError:
                    print("Invalid -n value passed")
                    exit()
        i += 1
   
    # Print the value of N being used to calculate pi
    print(f"Calculating pi with N = {N}")
     
    # Calculate the number of collisions required to approximate pi
    number_of_collisions = calculate_collisions(N, display)     
    
    # Print the approximation of pi
    print(f"Pi is approximately: {number_of_collisions / 10**N}") 
   
def calculate_collisions(N, display = False):
    
    # Set up particles with correct masses (infinite for wall, and mass ratio for the other two particles)
    # along with almost arbitrary widths, positions, and velocities.
    particles = Particles()
    
    particles.add_particle(Particle(mass = float("inf"),
                                    width = 1,
                                    position = 0,
                                    velocity = 0))
                           
    particles.add_particle(Particle(mass = 1,
                                    width = 5,
                                    position = 5,
                                    velocity = 0))
                           
    particles.add_particle(Particle(mass = 100**N,
                                    width = 5,
                                    position = 20,
                                    velocity = -10))
    
    number_of_collisions = 0
   
    # Set up display data if requested and take a snapshot to be displayed later
    if display:
        data = [(particles.deep_copy(), number_of_collisions)]
        elapsed_time = 0
        frames_per_second = 60
    
    p1_index = None
    
    # Loop until no more collisions
    while True:
   
        # Alternate between checking for collision between indices 0 and 1 (wall and small mass)
        # and between indices 1 and 2 (small mass and large mass)
        if p1_index == 1:
            p1_index = 0
        else:
            p1_index = 1
        
        # Get time to collision between particles p1_index and p1_index + 1 
        # The particles are sorted by position so particles involved in collision must have adjacent indecies
        time = particles.time_to_collide(p1_index, p1_index + 1)
        
        # If there are no more collisions, stop and display data if requested
        if time == None or time == float("inf"):
           
            # Continue to update particles for 3 seconds after there are no more collision and continue to 
            # add a snapshot of particles and number of collisions to the data array to be displayed
            # done to visually show there are no more collisions
            if display:
                for i in range(3*frames_per_second):
                    particles.update_particles_after_time(1 / frames_per_second - elapsed_time)
                    data.append((particles.deep_copy(), number_of_collisions))
                    elapsed_time = 0 
            
                display_data(data)
            
            return number_of_collisions
            
        if display:
            #simulate and record the time before the collision
            while True:
                # If there are no more frames before the next collision break out of the loop 
                if time + elapsed_time < 1 / frames_per_second:
                    elapsed_time += time
                    break
                else:
                    # Update all the particles in the collection by the remaining time in the frame, and take a snapshot
                    particles.update_particles_after_time(1 / frames_per_second - elapsed_time)
                    
                    data.append((particles.deep_copy(), number_of_collisions))
                    
                    #reduce the time until next collision and reset the frame timer
                    time -= 1 / frames_per_second - elapsed_time
                    elapsed_time = 0     
        else:
            # Update particles to time of collision
            particles.update_particles_after_time(time)
            
        # Calculate and update the velocities of particles after collision
        particles.update_particle_velocity_after_collision(p1_index, p1_index + 1)
        
        number_of_collisions += 1
        
        # User feedback to ensure the program has not stalled
        if number_of_collisions % 1_000_000 == 0:
            print("Number of collision so far: " + str(number_of_collisions))
   
def display_data(data):
    """
    Displays an animation of particle collisions.
    
    Parameters:
    - data (list): A list of particle and collision data used to display the animation
    
    Returns:
    None
    """
    
    def update(frame):
        """
        Updates the animation to display the data for the given frame.
        
        Parameters:
        - frame (int): The index of the frame to update the animation with
        
        Returns:
        - ax (AxesSubplot): The updated subplot with the current frame of the animation
        """
        ax.clear()
        
        # Determine the maximum x-axis value needed based on the position and width of the particles
        #particle 2 will always be the limiting factor of the x-axis length
        max_pos = max(data[0][0].particles[2].position, data[-1][0].particles[2].position)
        
        # Set the x and y limits of the subplot
        ax.set_xlim(0, max_pos + data[0][0].particles[2].width)
        ax.set_ylim(0, max_pos + data[0][0].particles[2].width)
        
        # Get the wall, particles, and number of collisions for the current frame
        particles, num_collisions = data[frame]
        wall = particles.particles[0]
        particle1 = particles.particles[1]
        particle2 = particles.particles[2]
       
        # Add a rectangle for the wall
        ax.add_patch(patches.Rectangle((wall.position, 0), wall.width, ax.get_ylim()[1], facecolor='black'))
        
        # Add rectangles for each particle, with red and blue colors indicating which particle is which
        ax.add_patch(patches.Rectangle((particle1.position, 0), particle1.width, particle1.width, facecolor='red'))
        ax.add_patch(patches.Rectangle((particle2.position, 0), particle2.width, particle2.width, facecolor='blue'))
        
        # Add a text box displaying the current number of collisions
        ax.text(0.2, 0.95, f'Collisions: {num_collisions}', transform=ax.transAxes)
        
        return ax
        
    # Create the subplot and animation object
    fig, ax = plt.subplots()
    ani = animation.FuncAnimation(fig, update, frames = len(data), interval =  0, repeat=False)

    # Display the animation
    plt.show()

def testing():
    test_particle()
    test_particles()
    test_calculate_collisions()
    print("All tests passed.")
    
def test_particle():
    print("Testing moving single particle after time")
    particle1 = Particle(1,1,0,1)
    
    particle1.update_after_time(0.5)
    
    assert particle1.mass == 1
    assert particle1.width == 1
    assert particle1.position == 0.5
    assert particle1.velocity == 1
    
    particle1.update_after_time(1.5)
    
    assert particle1.mass == 1
    assert particle1.width == 1
    assert particle1.position == 2
    assert particle1.velocity == 1
    
    particle1.update_after_time(0)
    
    assert particle1.mass == 1
    assert particle1.width == 1
    assert particle1.position == 2
    assert particle1.velocity == 1
    print("Passed")
    print()
    
    print("Testing particle deep_copy")
    particle2 = particle1.deep_copy()
    assert particle1 != particle2
    assert particle1.mass == particle2.mass
    assert particle1.width == particle2.width
    assert particle1.position == particle2.position
    assert particle1.velocity == particle2.velocity
    print("Passed")
    print()
    
def test_particles():
    print("Testing adding particles in arbitrary order")
    particle1 = Particle(mass = 1, width = 1, position = 0, velocity = 1)
    particle2 = Particle(mass = 1, width = 1, position = 5, velocity = -1)

    # Test add particles in arbitrary order, or by list
    particles = Particles()
    particles.add_particle(particle1)
    particles.add_particle(particle2)
    
    particles1 = Particles()
    particles1.add_particle(particle2)
    particles1.add_particle(particle1)
    
    particles2 = Particles([particle2, particle1])
    
    assert particles.particles == particles1.particles == particles2.particles
    assert len(particles.particles) == 2
    print("Passed")
    print()
    
    print("Testing time_to_collide")
    particle1 = Particle(mass = 1, width = 1, position = 0, velocity = 1)
    particle2 = Particle(mass = 1, width = 1, position = 10, velocity = -1)
    particle3 = Particle(mass = 1, width = 1, position = 20, velocity = 1)
    particle4 = Particle(mass = 1, width = 1, position = 30, velocity = 10)
    
    particles = Particles([particle1, particle2, particle3, particle4])
    assert particles.time_to_collide(0, 1) == 4.5
    assert particles.time_to_collide(0, 2) == float("inf")
    assert particles.time_to_collide(0, 3) == None
    print("Passed")
    print()
    
    print("Testing update_particles_after_time")
    particles.update_particles_after_time(4.5)
    assert particle1.position == 4.5
    assert particle2.position == 5.5
    assert particle3.position == 24.5
    assert particle4.position == 75
    print("Passed")
    print()
    
    print("Testing velocity_after_collision")
   
    # Particle properties gotten from wikipedia article on elastic collisions
    particle1 = Particle(mass = 3, velocity = 4, width = 1, position = 1)
    particle2 = Particle(mass = 5, velocity = -6, width = 1, position = 10)
    particle3 = Particle(mass = float("inf"), velocity = 0, width = 1, position = 20)
    
    particles = Particles([particle1, particle2, particle3])
    particles.update_particle_velocity_after_collision(0, 1)
    assert particle1.velocity == -8.5
    assert particle2.velocity == 1.5
    
    particles.update_particle_velocity_after_collision(1, 2)
    assert particle2.velocity == -1.5
    assert particle3.velocity == 0
    
    print("Passed")
    print()
    
    print("Testing particles deep_copy")
    particles1 = particles.deep_copy()
    assert particles != particle1
    for i in range(len(particles.particles)):
        assert particles.particles[i] != particles1.particles[i]
        assert particles.particles[i].mass == particles1.particles[i].mass
        assert particles.particles[i].width == particles1.particles[i].width
        assert particles.particles[i].position == particles1.particles[i].position
        assert particles.particles[i].velocity == particles1.particles[i].velocity
    print("Passed")
    print()

def test_calculate_collisions(N = 5):
    print("Testing pi calculation")
    for i in range(0, N):
        print(f"\t Testing N = {i}")
        assert calculate_collisions(i) == int(math.pi * 10**i)
        print(f"\t N = {i} passed")
        print()
    
    print("Passed")
    print()

if __name__ == "__main__":
    # This enables ctrl-c to quit mid-execution of the program
    def signal_handler(sig, frame):
        print(number_of_collisions)
        print('\nExiting...')
        sys.exit(0)
        
    try:
        signal.signal(signal.SIGTSTP, signal_handler)
    except AttributeError:
        pass

    signal.signal(signal.SIGINT, signal_handler) 
    main()
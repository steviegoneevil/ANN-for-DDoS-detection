'''
Created on 12 Feb 2018

@author: Stephen
'''
import matplotlib.pyplot as plt
import numpy as np
from sklearn.neural_network import MLPClassifier as MLP

def main():

    def draw_neural_net(ax, left, right, bottom, top, layer_sizes,coefs_,intercepts_,n_iter_,loss_,np, plt):
        n_layers = len(layer_sizes)
        v_spacing = (top - bottom)/float(max(layer_sizes))
        h_spacing = (right - left)/float(len(layer_sizes) - 1)
        # Input-Arrows
        layer_top_0 = v_spacing*(layer_sizes[0] - 1)/2. + (top + bottom)/2.
        for m in range(layer_sizes[0]):
            plt.arrow(left-0.18, layer_top_0 - m*v_spacing, 0.12, 0,  lw =1, head_width=0.01, head_length=0.02)
        # Nodes
        for n, layer_size in enumerate(layer_sizes):
            layer_top = v_spacing*(layer_size - 1)/2. + (top + bottom)/2.
            for m in range(layer_size):
                circle = plt.Circle((n*h_spacing + left, layer_top - m*v_spacing), v_spacing/8.,\
                                    color='w', ec='k', zorder=4)
                plt.plot((n*h_spacing) + left, layer_top - (m*v_spacing), 'o', mfc='w', mec='k', ls= '-', markersize = 40)
        # Add texts
                if n == 0:
                    plt.text(left-0.125, layer_top - m*v_spacing, r'$X_{'+str(m+1)+'}$', fontsize=15)
                elif (n_layers == 3) & (n == 1):
                    plt.text(n*h_spacing + left+0.00, layer_top - m*v_spacing+ (v_spacing/8.+0.01*v_spacing), r'$H_{'+str(m+1)+'}$', fontsize=15)
                elif n == n_layers -1:
                    plt.text(n*h_spacing + left+0.10, layer_top - m*v_spacing, r'$y_{'+str(m+1)+'}$', fontsize=15)
                ax.add_artist(circle)# 
        # Bias-Nodes
        for n, layer_size in enumerate(layer_sizes):
            if n < n_layers -1:
                x_bias = (n+0.5)*h_spacing + left
                y_bias = top + 0.005
                circle = plt.Circle((x_bias, y_bias), v_spacing/8.,\
                                    color='w', ec='k', zorder=4)
        # Add texts
                plt.text(x_bias-(v_spacing/8.+0.10*v_spacing+0.01), y_bias, r'$1$', fontsize=15)
                ax.add_artist(circle)   
        # Edges between nodes
        for n, (layer_size_a, layer_size_b) in enumerate(zip(layer_sizes[:-1], layer_sizes[1:])):
            layer_top_a = v_spacing*(layer_size_a - 1)/2. + (top + bottom)/2.
            layer_top_b = v_spacing*(layer_size_b - 1)/2. + (top + bottom)/2.
            for m in range(layer_size_a):
                print(m)
                for o in range(layer_size_b):
                    line = plt.Line2D([n*h_spacing + left, (n + 1)*h_spacing + left],
                                      [layer_top_a - m*v_spacing, layer_top_b - o*v_spacing], c='k')
                    ax.add_artist(line)
                    xm = (n*h_spacing + left)
                    xo = ((n + 1)*h_spacing + left)
                    ym = (layer_top_a - m*v_spacing)
                    yo = (layer_top_b - o*v_spacing)
                    rot_mo_rad = np.arctan((yo-ym)/(xo-xm))
                    rot_mo_deg = rot_mo_rad*180./np.pi
                    xm1 = xm + (v_spacing/8.+0.05)*np.cos(rot_mo_rad)
                    if n == 0:
                        if yo > ym:
                            ym1 = ym + (v_spacing/8.+0.12)*np.sin(rot_mo_rad)
                        else:
                            ym1 = ym + (v_spacing/8.+0.05)*np.sin(rot_mo_rad)
                    else:
                        if yo > ym:
                            ym1 = ym + (v_spacing/8.+0.12)*np.sin(rot_mo_rad)
                        else:
                            ym1 = ym + (v_spacing/8.+0.04)*np.sin(rot_mo_rad)
                    plt.text( xm1, ym1,\
                             str(round(coefs_[n][m, o],4)),\
                             rotation = rot_mo_deg, \
                             fontsize = 10)
        # Edges between bias and nodes
        for n, (layer_size_a, layer_size_b) in enumerate(zip(layer_sizes[:-1], layer_sizes[1:])):
            if n < n_layers-1:
                layer_top_a = v_spacing*(layer_size_a - 1)/2. + (top + bottom)/2.
                layer_top_b = v_spacing*(layer_size_b - 1)/2. + (top + bottom)/2.

            for m in range(layer_size_a):
                x_bias = (n+0.5)*h_spacing + left
                y_bias = top + 0.005 
                for o in range(layer_size_b):
                    print(o)
                    line = plt.Line2D([x_bias, (n + 1)*h_spacing + left],
                                  [y_bias, layer_top_b - o*v_spacing], c='k')
                    ax.add_artist(line)
                    xo = ((n + 1)*h_spacing + left)
                    yo = (layer_top_b - o*v_spacing)
                    rot_bo_rad = np.arctan((yo-y_bias)/(xo-x_bias))
                    rot_bo_deg = rot_bo_rad*180./np.pi
                    xo2 = xo - (v_spacing/8.+0.01)*np.cos(rot_bo_rad)
                    yo2 = yo - (v_spacing/8.+0.01)*np.sin(rot_bo_rad)
                    xo1 = xo2 -0.05 *np.cos(rot_bo_rad)
                    yo1 = yo2 -0.05 *np.sin(rot_bo_rad)
                    plt.text( xo1, yo1,\
                         str(round(intercepts_[n][o],4)),\
                         rotation = rot_bo_deg, \
                         fontsize = 10)    
        # Output-Arrows
        layer_top_0 = v_spacing*(layer_sizes[-1] - 1)/2. + (top + bottom)/2.
        for m in range(layer_sizes[-1]):
            plt.arrow(right+0.015, layer_top_0 - m*v_spacing, 0.16*h_spacing, 0,  lw =1, head_width=0.01, head_length=0.02)
        # Record the n_iter_ and loss
        plt.text(left + (right-left)/3., bottom - 0.005*v_spacing, \
        'Steps:'+str(n_iter_)+'    Loss: ' + str(round(loss_, 6)), fontsize = 15)


    
    
    dataset = np.mat('-1 -1 -1; -1 1 1; 1 -1 1; 1 1 -1')
    X_train = [[-1, -1], [-1, 1], [1, -1], [1, 1]]
    y_train = [-1, 1, 1, -1]
    
    my_hidden_layer_sizes= (2,2)
    
    XOR_MLP = MLP(
                activation='tanh',
                alpha=0.,
                batch_size='auto',
                beta_1=0.9,
                beta_2=0.999,
                early_stopping=False,
                epsilon=1e-08,
                hidden_layer_sizes= my_hidden_layer_sizes,
                learning_rate='constant',
                learning_rate_init = 0.1,
                max_iter=5000,
                momentum=0.5,
                nesterovs_momentum=True,
                power_t=0.5,
                random_state=0,
                shuffle=True,
                solver='sgd',
                tol=0.0001,
                validation_fraction=0.1,
                verbose=False,
                warm_start=False)
    
    
    
    
    XOR_MLP.fit(X_train,y_train)
    
    fig66 = plt.figure(figsize=(6, 6))
    ax = fig66.gca()
    ax.axis('off')
    
    


    draw_neural_net(ax, .1, .9, .1, .9, [2, 2, 1],
    XOR_MLP.coefs_,
    XOR_MLP.intercepts_,
    XOR_MLP.n_iter_,
    XOR_MLP.loss_,
    np, plt)
    plt.savefig('fig66_nn.png')
    
main()